"""BGP-LS Topology Collector — application entry point.

Starts:
  1.  BGPServer   — listens on TCP 179 for Nokia SROS router connections.
  2.  TopologyManager — processes BGP-LS UPDATEs and maintains the graph.
  3.  FastAPI / uvicorn — exposes REST + WebSocket API.

Usage::

    python -m bgp_ls_collector.main [--config config.yaml] [--help]
    # or via the installed CLI entry-point:
    bgp-ls-collector --config config.yaml
"""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path

import uvicorn
from loguru import logger

from .api.app import create_app
from .bgp.session import BGPServer, PeerConfig
from .config import AppConfig, load_config
from .topology.graph import TopologyGraph
from .topology.manager import TopologyManager


def _configure_logging(level: str, fmt: str) -> None:
    logger.remove()
    if fmt == "json":
        logger.add(
            sys.stderr,
            level=level,
            serialize=True,
        )
    else:
        logger.add(
            sys.stderr,
            level=level,
            format=(
                "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
                "<level>{level: <8}</level> | "
                "<cyan>{name}</cyan>:<cyan>{line}</cyan> — "
                "<level>{message}</level>"
            ),
        )


async def _run(cfg: AppConfig) -> None:
    """Async main: start BGP server + API server concurrently."""

    # ---- Topology graph (shared between BGP and API layers) ----
    graph = TopologyGraph()

    # ---- Topology manager ----
    manager = TopologyManager(graph)

    # ---- BGP server ----
    bgp_server = BGPServer(
        local_as=cfg.local_as,
        local_router_id=cfg.router_id,
        bind_address=cfg.bgp_bind,
        port=cfg.bgp_port,
        hold_time=cfg.hold_time,
        update_cb=manager.on_update,
        allow_dynamic=cfg.allow_dynamic_peers,
    )

    for peer in cfg.peers:
        bgp_server.add_peer(
            neighbor_ip=peer.neighbor_ip,
            remote_as=peer.remote_as,
            hold_time=peer.hold_time or cfg.hold_time,
            connect_retry=peer.connect_retry or cfg.connect_retry,
            passive=peer.passive,
        )

    if cfg.peers:
        logger.info(f"Configured {len(cfg.peers)} BGP peer(s)")
    elif cfg.allow_dynamic_peers:
        logger.info("Dynamic peer acceptance enabled")
    else:
        logger.warning(
            "No peers configured and allow_dynamic_peers=false. "
            "No BGP sessions will be accepted."
        )

    # ---- FastAPI app ----
    fastapi_app = create_app(
        graph=graph,
        get_peer_states=bgp_server.get_peer_states,
    )
    # Wire topology manager change callback to WebSocket broadcaster
    manager._change_cb = fastapi_app.state.topology_change_cb

    # ---- uvicorn config (programmatic, no CLI) ----
    uv_config = uvicorn.Config(
        app=fastapi_app,
        host=cfg.api_host,
        port=cfg.api_port,
        log_level=cfg.log_level.lower(),
        access_log=False,
    )
    uv_server = uvicorn.Server(uv_config)

    logger.info(
        f"Starting BGP-LS Collector — "
        f"BGP={cfg.bgp_bind}:{cfg.bgp_port} "
        f"AS={cfg.local_as} RID={cfg.router_id} | "
        f"API={cfg.api_host}:{cfg.api_port}"
    )

    # Run both BGP server and uvicorn concurrently
    await asyncio.gather(
        bgp_server.start(),
        uv_server.serve(),
    )


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(
        prog="bgp-ls-collector",
        description="BGP-LS Topology Collector for Nokia SROS Routers",
    )
    parser.add_argument(
        "--config",
        metavar="FILE",
        default=None,
        help="Path to YAML configuration file (default: config.yaml if present)",
    )
    parser.add_argument(
        "--local-as",
        type=int,
        default=None,
        help="Local BGP AS number (overrides config)",
    )
    parser.add_argument(
        "--router-id",
        default=None,
        help="BGP Router-ID in dotted-quad notation (overrides config)",
    )
    parser.add_argument(
        "--bgp-port",
        type=int,
        default=None,
        help="TCP port for BGP listener (default: 179)",
    )
    parser.add_argument(
        "--api-port",
        type=int,
        default=None,
        help="TCP port for REST API (default: 8080)",
    )
    parser.add_argument(
        "--log-level",
        choices=["TRACE", "DEBUG", "INFO", "WARNING", "ERROR"],
        default=None,
    )
    parser.add_argument(
        "--allow-dynamic",
        action="store_true",
        default=None,
        help="Accept BGP connections from any peer (no pre-configured neighbor required)",
    )

    args = parser.parse_args(argv)

    # Determine config file
    config_path = args.config
    if config_path is None and Path("config.yaml").exists():
        config_path = "config.yaml"

    cfg = load_config(config_path)

    # CLI overrides
    if args.local_as:
        cfg.local_as = args.local_as
    if args.router_id:
        cfg.router_id = args.router_id
    if args.bgp_port:
        cfg.bgp_port = args.bgp_port
    if args.api_port:
        cfg.api_port = args.api_port
    if args.log_level:
        cfg.log_level = args.log_level
    if args.allow_dynamic:
        cfg.allow_dynamic_peers = True

    _configure_logging(cfg.log_level, cfg.log_format)

    try:
        asyncio.run(_run(cfg))
    except KeyboardInterrupt:
        logger.info("Shutting down")


if __name__ == "__main__":
    main()
