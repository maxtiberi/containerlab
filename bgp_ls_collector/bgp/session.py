"""BGP session FSM (RFC 4271).

Each peer connection runs its own BGPSession coroutine.  The session:
  1. Completes OPEN / KEEPALIVE handshake.
  2. Sends periodic KEEPALIVE messages.
  3. Feeds every UPDATE message to the supplied *update_callback*.
  4. Handles NOTIFICATION and graceful shutdown.
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Awaitable

from loguru import logger

from .constants import (
    AFI_BGP_LS,
    ERR_CEASE,
    ERR_FSM,
    ERR_HOLD_TIMER_EXPIRED,
    MSG_KEEPALIVE,
    MSG_NOTIFICATION,
    MSG_OPEN,
    MSG_UPDATE,
    SAFI_BGPLS,
    STATE_ESTABLISHED,
    STATE_IDLE,
    STATE_OPENCONFIRM,
    STATE_OPENSENT,
)
from .messages import (
    BGPParseError,
    OpenMessage,
    UpdateMessage,
    decode_notification,
    decode_open,
    decode_update,
    encode_keepalive,
    encode_notification,
    encode_open,
    read_message,
)


@dataclass
class PeerConfig:
    """Configuration for a single BGP peer."""
    neighbor_ip: str
    remote_as: int
    local_as: int
    local_router_id: str
    hold_time: int = 90
    connect_retry: int = 30     # seconds between reconnect attempts
    passive: bool = True        # True = we listen; False = we connect


@dataclass
class PeerState:
    """Runtime state for a BGP peer session."""
    config: PeerConfig
    state: str = STATE_IDLE
    remote_bgp_id: str = ""
    negotiated_hold_time: int = 0
    remote_as: int = 0          # resolved (4-byte) remote AS
    uptime: float = 0.0
    prefixes_received: int = 0
    last_error: str = ""
    connected: bool = False


UpdateCallback = Callable[["BGPSession", UpdateMessage], Awaitable[None]]
StateCallback = Callable[["BGPSession", str, str], Awaitable[None]]


class BGPSession:
    """
    Manages one BGP session to a single peer.

    Args:
        config:          PeerConfig for this peer.
        update_cb:       Async callback invoked for each UPDATE message.
        state_cb:        Optional async callback invoked on state transitions.
    """

    def __init__(
        self,
        config: PeerConfig,
        update_cb: UpdateCallback,
        state_cb: StateCallback | None = None,
    ) -> None:
        self.config = config
        self._update_cb = update_cb
        self._state_cb = state_cb
        self.state = PeerState(config=config)
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._keepalive_task: asyncio.Task | None = None
        self._hold_deadline: float = 0.0
        self._stop_event = asyncio.Event()

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    async def run_passive(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        """Handle an already-established TCP connection (passive/server mode)."""
        self._reader = reader
        self._writer = writer
        peer_addr = writer.get_extra_info("peername", ("?", 0))
        logger.info(
            f"[{self.config.neighbor_ip}] Incoming TCP connection from {peer_addr[0]}:{peer_addr[1]}"
        )
        await self._run_session()

    async def run_active(self) -> None:
        """Actively connect to peer and maintain the session with reconnects."""
        while not self._stop_event.is_set():
            try:
                logger.info(
                    f"[{self.config.neighbor_ip}] Connecting to {self.config.neighbor_ip}:179"
                )
                reader, writer = await asyncio.open_connection(
                    self.config.neighbor_ip, 179
                )
                self._reader = reader
                self._writer = writer
                await self._run_session()
            except (ConnectionRefusedError, OSError) as exc:
                logger.warning(
                    f"[{self.config.neighbor_ip}] Connection failed: {exc}. "
                    f"Retrying in {self.config.connect_retry}s"
                )
            except asyncio.CancelledError:
                break
            if not self._stop_event.is_set():
                await asyncio.sleep(self.config.connect_retry)

    def stop(self) -> None:
        self._stop_event.set()
        if self._writer and not self._writer.is_closing():
            try:
                self._writer.write(
                    encode_notification(ERR_CEASE, 2)  # Administrative Shutdown
                )
            except Exception:
                pass
            self._writer.close()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _set_state(self, new_state: str) -> None:
        old = self.state.state
        self.state.state = new_state
        logger.debug(f"[{self.config.neighbor_ip}] FSM {old} → {new_state}")
        if self._state_cb:
            await self._state_cb(self, old, new_state)

    async def _send(self, data: bytes) -> None:
        if self._writer and not self._writer.is_closing():
            self._writer.write(data)
            await self._writer.drain()

    async def _run_session(self) -> None:
        await self._set_state("CONNECT")
        try:
            await self._do_open()
            await self._receive_loop()
        except BGPParseError as exc:
            logger.error(f"[{self.config.neighbor_ip}] Parse error: {exc}")
            self.state.last_error = str(exc)
            await self._send(encode_notification(ERR_FSM, 0))
        except asyncio.IncompleteReadError:
            logger.warning(f"[{self.config.neighbor_ip}] Connection closed by peer")
        except Exception as exc:
            logger.exception(f"[{self.config.neighbor_ip}] Unexpected error: {exc}")
            self.state.last_error = str(exc)
        finally:
            await self._cleanup()

    async def _do_open(self) -> None:
        """Send OPEN and receive + validate peer OPEN."""
        await self._set_state(STATE_OPENSENT)
        await self._send(
            encode_open(
                local_as=self.config.local_as,
                hold_time=self.config.hold_time,
                router_id=self.config.local_router_id,
            )
        )
        msg_type, body = await asyncio.wait_for(
            read_message(self._reader), timeout=30.0
        )
        if msg_type != MSG_OPEN:
            raise BGPParseError(f"Expected OPEN, got type={msg_type}")

        peer_open = decode_open(body)
        self._validate_open(peer_open)

        # Negotiate hold time
        self.state.negotiated_hold_time = min(
            self.config.hold_time, peer_open.hold_time
        )
        self.state.remote_bgp_id = peer_open.bgp_id
        self.state.remote_as = peer_open.four_byte_as or peer_open.peer_as
        self.state.connected = True

        logger.info(
            f"[{self.config.neighbor_ip}] OPEN received: peer-AS={self.state.remote_as} "
            f"BGP-ID={self.state.remote_bgp_id} hold={self.state.negotiated_hold_time}s"
        )

        # Send KEEPALIVE to confirm OPEN
        await self._set_state(STATE_OPENCONFIRM)
        await self._send(encode_keepalive())

        # Wait for peer's KEEPALIVE
        msg_type, body = await asyncio.wait_for(
            read_message(self._reader), timeout=30.0
        )
        if msg_type == MSG_KEEPALIVE:
            pass
        elif msg_type == MSG_NOTIFICATION:
            notif = decode_notification(body)
            raise BGPParseError(
                f"NOTIFICATION during OPEN: code={notif.error_code} sub={notif.error_subcode}"
            )
        else:
            raise BGPParseError(f"Expected KEEPALIVE, got type={msg_type}")

        await self._set_state(STATE_ESTABLISHED)
        self.state.uptime = time.time()
        logger.info(
            f"[{self.config.neighbor_ip}] Session ESTABLISHED "
            f"(AS={self.state.remote_as}, BGP-ID={self.state.remote_bgp_id})"
        )

        # Start keepalive sender
        if self.state.negotiated_hold_time > 0:
            ka_interval = self.state.negotiated_hold_time // 3
            self._keepalive_task = asyncio.create_task(
                self._keepalive_sender(ka_interval)
            )
        self._hold_deadline = (
            time.time() + self.state.negotiated_hold_time
            if self.state.negotiated_hold_time > 0
            else float("inf")
        )

    def _validate_open(self, msg: OpenMessage) -> None:
        """Basic validation of received OPEN message."""
        if msg.version != 4:
            raise BGPParseError(f"Unsupported BGP version: {msg.version}")
        if msg.hold_time != 0 and msg.hold_time < 3:
            raise BGPParseError(f"Unacceptable hold time: {msg.hold_time}")
        # Check that peer advertises BGP-LS capability
        has_bgpls = any(
            c.code == 1 and len(c.data) >= 4 and
            c.data[0:2] == bytes([AFI_BGP_LS >> 8, AFI_BGP_LS & 0xFF]) and
            c.data[3] == SAFI_BGPLS
            for c in msg.capabilities
        )
        if not has_bgpls:
            logger.warning(
                f"[{self.config.neighbor_ip}] Peer did not advertise BGP-LS capability — "
                "will still proceed but may receive no BGP-LS updates"
            )

    async def _receive_loop(self) -> None:
        """Main receive loop while session is ESTABLISHED."""
        while not self._stop_event.is_set():
            # Check hold timer
            if self.state.negotiated_hold_time > 0:
                remaining = self._hold_deadline - time.time()
                if remaining <= 0:
                    logger.error(f"[{self.config.neighbor_ip}] Hold timer expired")
                    await self._send(encode_notification(ERR_HOLD_TIMER_EXPIRED, 0))
                    return
                timeout = min(remaining, 5.0)
            else:
                timeout = 5.0

            try:
                msg_type, body = await asyncio.wait_for(
                    read_message(self._reader), timeout=timeout
                )
            except asyncio.TimeoutError:
                continue  # loop back to check hold timer

            # Reset hold deadline on any received message
            if self.state.negotiated_hold_time > 0:
                self._hold_deadline = time.time() + self.state.negotiated_hold_time

            if msg_type == MSG_KEEPALIVE:
                logger.trace(f"[{self.config.neighbor_ip}] KEEPALIVE received")
            elif msg_type == MSG_UPDATE:
                try:
                    update = decode_update(body)
                    self.state.prefixes_received += 1
                    await self._update_cb(self, update)
                except BGPParseError as exc:
                    logger.warning(
                        f"[{self.config.neighbor_ip}] Failed to parse UPDATE: {exc}"
                    )
            elif msg_type == MSG_NOTIFICATION:
                notif = decode_notification(body)
                logger.warning(
                    f"[{self.config.neighbor_ip}] NOTIFICATION: "
                    f"code={notif.error_code} sub={notif.error_subcode}"
                )
                return
            else:
                logger.warning(
                    f"[{self.config.neighbor_ip}] Unknown message type={msg_type}"
                )

    async def _keepalive_sender(self, interval: int) -> None:
        """Periodically send KEEPALIVE messages."""
        while not self._stop_event.is_set():
            await asyncio.sleep(interval)
            if self.state.state == STATE_ESTABLISHED:
                try:
                    await self._send(encode_keepalive())
                    logger.trace(f"[{self.config.neighbor_ip}] KEEPALIVE sent")
                except Exception as exc:
                    logger.warning(f"[{self.config.neighbor_ip}] Failed to send KEEPALIVE: {exc}")
                    return

    async def _cleanup(self) -> None:
        if self._keepalive_task and not self._keepalive_task.done():
            self._keepalive_task.cancel()
        if self._writer and not self._writer.is_closing():
            self._writer.close()
            try:
                await self._writer.wait_closed()
            except Exception:
                pass
        self.state.connected = False
        await self._set_state(STATE_IDLE)
        logger.info(f"[{self.config.neighbor_ip}] Session closed")


# ---------------------------------------------------------------------------
# BGP Server — listens for incoming connections, spawns sessions
# ---------------------------------------------------------------------------

class BGPServer:
    """
    Listens on TCP 179 for BGP connections from Nokia SROS routers.

    Known peers are looked up by remote IP; unknown peers are rejected unless
    *allow_dynamic* is True.
    """

    def __init__(
        self,
        local_as: int,
        local_router_id: str,
        bind_address: str = "0.0.0.0",
        port: int = 179,
        hold_time: int = 90,
        update_cb: UpdateCallback | None = None,
        state_cb: StateCallback | None = None,
        allow_dynamic: bool = False,
    ) -> None:
        self.local_as = local_as
        self.local_router_id = local_router_id
        self.bind_address = bind_address
        self.port = port
        self.hold_time = hold_time
        self._update_cb = update_cb or self._default_update_cb
        self._state_cb = state_cb
        self.allow_dynamic = allow_dynamic

        self._peers: dict[str, PeerConfig] = {}   # keyed by neighbor_ip
        self.sessions: dict[str, BGPSession] = {}  # active sessions
        self._server: asyncio.Server | None = None
        self._active_tasks: list[asyncio.Task] = []

    def add_peer(self, neighbor_ip: str, remote_as: int, **kwargs) -> None:
        """Register a known peer (passive mode — peer connects to us)."""
        self._peers[neighbor_ip] = PeerConfig(
            neighbor_ip=neighbor_ip,
            remote_as=remote_as,
            local_as=self.local_as,
            local_router_id=self.local_router_id,
            hold_time=self.hold_time,
            passive=True,
            **kwargs,
        )

    async def start(self) -> None:
        """Start the BGP server coroutine."""
        self._server = await asyncio.start_server(
            self._handle_connection,
            host=self.bind_address,
            port=self.port,
        )
        addr = self._server.sockets[0].getsockname()
        logger.info(
            f"BGP server listening on {addr[0]}:{addr[1]} "
            f"(AS={self.local_as}, Router-ID={self.local_router_id})"
        )
        async with self._server:
            await self._server.serve_forever()

    async def _handle_connection(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        peer_ip, peer_port = writer.get_extra_info("peername", ("?", 0))
        logger.info(f"TCP connection from {peer_ip}:{peer_port}")

        cfg = self._peers.get(peer_ip)
        if cfg is None:
            if self.allow_dynamic:
                cfg = PeerConfig(
                    neighbor_ip=peer_ip,
                    remote_as=0,  # will be validated from OPEN
                    local_as=self.local_as,
                    local_router_id=self.local_router_id,
                    hold_time=self.hold_time,
                    passive=True,
                )
            else:
                logger.warning(f"Rejecting unknown peer {peer_ip}")
                writer.close()
                return

        session = BGPSession(
            config=cfg,
            update_cb=self._update_cb,
            state_cb=self._state_cb,
        )
        self.sessions[peer_ip] = session
        task = asyncio.create_task(session.run_passive(reader, writer))
        self._active_tasks.append(task)
        task.add_done_callback(
            lambda t: (
                self.sessions.pop(peer_ip, None),
                self._active_tasks.remove(t) if t in self._active_tasks else None,
            )
        )

    @staticmethod
    async def _default_update_cb(session: BGPSession, update: UpdateMessage) -> None:
        logger.debug(
            f"[{session.config.neighbor_ip}] UPDATE received "
            f"(mp_reach={update.mp_reach is not None})"
        )

    def get_peer_states(self) -> list[dict[str, Any]]:
        result = []
        for ip, session in self.sessions.items():
            s = session.state
            result.append(
                {
                    "neighbor_ip": ip,
                    "state": s.state,
                    "remote_as": s.remote_as,
                    "remote_bgp_id": s.remote_bgp_id,
                    "hold_time": s.negotiated_hold_time,
                    "uptime_seconds": (time.time() - s.uptime) if s.uptime else 0,
                    "prefixes_received": s.prefixes_received,
                    "last_error": s.last_error,
                }
            )
        return result
