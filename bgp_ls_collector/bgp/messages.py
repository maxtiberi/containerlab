"""BGP message encoding and decoding (RFC 4271, RFC 4760, RFC 6793)."""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass, field
from typing import Any

from .constants import (
    AFI_BGP_LS,
    BGP_HEADER_LEN,
    BGP_MARKER,
    CAP_4BYTE_AS,
    CAP_MULTIPROTOCOL,
    CAP_ROUTE_REFRESH,
    MSG_KEEPALIVE,
    MSG_NOTIFICATION,
    MSG_OPEN,
    MSG_UPDATE,
    OPT_PARAM_CAPABILITY,
    PA_BGP_LS,
    PA_FLAG_EXTENDED_LEN,
    PA_FLAG_OPTIONAL,
    PA_FLAG_TRANSITIVE,
    PA_MP_REACH_NLRI,
    PA_MP_UNREACH_NLRI,
    PA_ORIGIN,
    PA_AS_PATH,
    PA_LOCAL_PREF,
    PA_MULTI_EXIT_DISC,
    PA_NEXT_HOP,
    SAFI_BGPLS,
)


class BGPParseError(Exception):
    """Raised when a BGP message cannot be parsed."""


# ---------------------------------------------------------------------------
# Low-level helpers
# ---------------------------------------------------------------------------

def encode_header(msg_type: int, body: bytes) -> bytes:
    """Prepend BGP fixed header to *body*."""
    length = BGP_HEADER_LEN + len(body)
    return BGP_MARKER + struct.pack("!HB", length, msg_type) + body


def read_tlv(data: bytes, offset: int) -> tuple[int, int, bytes]:
    """
    Parse a Type-Length-Value at *offset*.

    Returns (type, length, value_bytes). Advances caller to offset + 4 + length.
    """
    if offset + 4 > len(data):
        raise BGPParseError("Truncated TLV header")
    t, l = struct.unpack_from("!HH", data, offset)
    end = offset + 4 + l
    if end > len(data):
        raise BGPParseError(f"TLV type={t} length={l} exceeds buffer")
    return t, l, data[offset + 4 : end]


# ---------------------------------------------------------------------------
# BGP OPEN message
# ---------------------------------------------------------------------------

@dataclass
class Capability:
    code: int
    data: bytes = b""


@dataclass
class OpenMessage:
    version: int
    peer_as: int          # 2-byte field; may be AS_TRANS (23456) for 4-byte AS
    hold_time: int
    bgp_id: str           # dotted-quad
    capabilities: list[Capability] = field(default_factory=list)
    # Resolved after capability negotiation
    four_byte_as: int | None = None  # value from CAP_4BYTE_AS if present


def encode_open(
    local_as: int,
    hold_time: int,
    router_id: str,
    extra_caps: list[Capability] | None = None,
) -> bytes:
    """Build a BGP OPEN message advertising BGP-LS capability."""
    caps: list[Capability] = [
        Capability(CAP_ROUTE_REFRESH),
        Capability(
            CAP_MULTIPROTOCOL,
            struct.pack("!HBB", AFI_BGP_LS, 0, SAFI_BGPLS),
        ),
    ]
    # Advertise 4-byte AS if needed
    wire_as = local_as if local_as <= 0xFFFF else 23456
    if local_as > 0xFFFF or True:  # always advertise 4-byte AS capability
        caps.append(Capability(CAP_4BYTE_AS, struct.pack("!I", local_as)))
    if extra_caps:
        caps.extend(extra_caps)

    # Encode capabilities as optional parameter
    cap_data = b""
    for cap in caps:
        cap_data += struct.pack("!BB", cap.code, len(cap.data)) + cap.data

    opt_params = struct.pack("!BB", OPT_PARAM_CAPABILITY, len(cap_data)) + cap_data

    bgp_id_bytes = socket.inet_aton(router_id)
    body = struct.pack("!BHHB", 4, wire_as, hold_time, len(opt_params))
    # insert BGP ID between hold_time and opt_parms_len
    body = struct.pack("!BHH", 4, wire_as, hold_time) + bgp_id_bytes + struct.pack("!B", len(opt_params)) + opt_params

    return encode_header(MSG_OPEN, body)


def decode_open(data: bytes) -> OpenMessage:
    """Parse a BGP OPEN message body (excluding fixed header)."""
    if len(data) < 10:
        raise BGPParseError("OPEN message too short")
    version, peer_as, hold_time = struct.unpack_from("!BHH", data, 0)
    bgp_id = socket.inet_ntoa(data[5:9])
    opt_len = data[9]
    offset = 10
    end = offset + opt_len

    capabilities: list[Capability] = []
    four_byte_as: int | None = None

    while offset < end:
        if offset + 2 > end:
            break
        param_type = data[offset]
        param_len = data[offset + 1]
        offset += 2
        param_data = data[offset : offset + param_len]
        offset += param_len

        if param_type == OPT_PARAM_CAPABILITY:
            ci = 0
            while ci < len(param_data):
                if ci + 2 > len(param_data):
                    break
                cap_code = param_data[ci]
                cap_len = param_data[ci + 1]
                ci += 2
                cap_value = param_data[ci : ci + cap_len]
                ci += cap_len
                capabilities.append(Capability(cap_code, cap_value))
                if cap_code == CAP_4BYTE_AS and cap_len >= 4:
                    four_byte_as = struct.unpack_from("!I", cap_value)[0]

    return OpenMessage(
        version=version,
        peer_as=peer_as,
        hold_time=hold_time,
        bgp_id=bgp_id,
        capabilities=capabilities,
        four_byte_as=four_byte_as,
    )


# ---------------------------------------------------------------------------
# BGP KEEPALIVE
# ---------------------------------------------------------------------------

def encode_keepalive() -> bytes:
    return encode_header(MSG_KEEPALIVE, b"")


# ---------------------------------------------------------------------------
# BGP NOTIFICATION
# ---------------------------------------------------------------------------

@dataclass
class NotificationMessage:
    error_code: int
    error_subcode: int
    data: bytes = b""


def encode_notification(error_code: int, error_subcode: int, data: bytes = b"") -> bytes:
    body = struct.pack("!BB", error_code, error_subcode) + data
    return encode_header(MSG_NOTIFICATION, body)


def decode_notification(data: bytes) -> NotificationMessage:
    if len(data) < 2:
        raise BGPParseError("NOTIFICATION too short")
    return NotificationMessage(
        error_code=data[0],
        error_subcode=data[1],
        data=data[2:],
    )


# ---------------------------------------------------------------------------
# BGP Path Attribute
# ---------------------------------------------------------------------------

@dataclass
class PathAttribute:
    flags: int
    type_code: int
    value: bytes

    @property
    def optional(self) -> bool:
        return bool(self.flags & PA_FLAG_OPTIONAL)

    @property
    def transitive(self) -> bool:
        return bool(self.flags & PA_FLAG_TRANSITIVE)

    @property
    def extended_length(self) -> bool:
        return bool(self.flags & PA_FLAG_EXTENDED_LEN)


def decode_path_attributes(data: bytes) -> list[PathAttribute]:
    """Decode sequence of BGP path attributes."""
    attrs: list[PathAttribute] = []
    offset = 0
    while offset < len(data):
        if offset + 2 > len(data):
            raise BGPParseError("Truncated path attribute header")
        flags = data[offset]
        type_code = data[offset + 1]
        offset += 2
        if flags & PA_FLAG_EXTENDED_LEN:
            if offset + 2 > len(data):
                raise BGPParseError("Truncated extended-length path attribute")
            attr_len = struct.unpack_from("!H", data, offset)[0]
            offset += 2
        else:
            if offset + 1 > len(data):
                raise BGPParseError("Truncated path attribute length")
            attr_len = data[offset]
            offset += 1
        value = data[offset : offset + attr_len]
        offset += attr_len
        attrs.append(PathAttribute(flags=flags, type_code=type_code, value=value))
    return attrs


# ---------------------------------------------------------------------------
# BGP UPDATE message
# ---------------------------------------------------------------------------

@dataclass
class UpdateMessage:
    withdrawn_routes: list[tuple[int, bytes]] = field(default_factory=list)
    path_attributes: list[PathAttribute] = field(default_factory=list)
    nlri: list[tuple[int, bytes]] = field(default_factory=list)

    # Convenience accessors populated by parse_update
    mp_reach: "MPReachNLRI | None" = field(default=None, repr=False)
    mp_unreach: "MPUnreachNLRI | None" = field(default=None, repr=False)
    bgpls_attr_raw: bytes | None = field(default=None, repr=False)


@dataclass
class MPReachNLRI:
    afi: int
    safi: int
    next_hop: bytes
    nlri_data: bytes        # raw NLRI bytes (unparsed)


@dataclass
class MPUnreachNLRI:
    afi: int
    safi: int
    withdrawn_data: bytes   # raw withdrawn NLRI bytes (unparsed)


def decode_mp_reach(value: bytes) -> MPReachNLRI:
    if len(value) < 4:
        raise BGPParseError("MP_REACH_NLRI too short")
    afi = struct.unpack_from("!H", value, 0)[0]
    safi = value[2]
    nh_len = value[3]
    next_hop = value[4 : 4 + nh_len]
    # Skip reserved byte after next-hop
    offset = 4 + nh_len + 1
    nlri_data = value[offset:]
    return MPReachNLRI(afi=afi, safi=safi, next_hop=next_hop, nlri_data=nlri_data)


def decode_mp_unreach(value: bytes) -> MPUnreachNLRI:
    if len(value) < 3:
        raise BGPParseError("MP_UNREACH_NLRI too short")
    afi = struct.unpack_from("!H", value, 0)[0]
    safi = value[2]
    return MPUnreachNLRI(afi=afi, safi=safi, withdrawn_data=value[3:])


def decode_update(data: bytes) -> UpdateMessage:
    """Decode a BGP UPDATE message body (excluding fixed header)."""
    if len(data) < 4:
        raise BGPParseError("UPDATE message too short")

    offset = 0
    # Withdrawn routes
    wr_len = struct.unpack_from("!H", data, offset)[0]
    offset += 2
    # (Ignored for IPv4 traditional NLRI — BGP-LS uses MP attributes only)
    offset += wr_len

    # Path attributes
    if offset + 2 > len(data):
        raise BGPParseError("UPDATE: missing path attribute length")
    pa_len = struct.unpack_from("!H", data, offset)[0]
    offset += 2
    pa_data = data[offset : offset + pa_len]
    offset += pa_len

    path_attrs = decode_path_attributes(pa_data)

    msg = UpdateMessage(path_attributes=path_attrs)

    for attr in path_attrs:
        if attr.type_code == PA_MP_REACH_NLRI:
            msg.mp_reach = decode_mp_reach(attr.value)
        elif attr.type_code == PA_MP_UNREACH_NLRI:
            msg.mp_unreach = decode_mp_unreach(attr.value)
        elif attr.type_code == PA_BGP_LS:
            msg.bgpls_attr_raw = attr.value

    return msg


# ---------------------------------------------------------------------------
# BGP message framing reader (async helper)
# ---------------------------------------------------------------------------

async def read_message(reader) -> tuple[int, bytes]:
    """
    Read one complete BGP message from *reader* (asyncio.StreamReader).

    Returns (msg_type, body_bytes) where body excludes the 19-byte header.
    Raises BGPParseError or asyncio.IncompleteReadError on errors.
    """
    header = await reader.readexactly(BGP_HEADER_LEN)
    if header[:16] != BGP_MARKER:
        raise BGPParseError("Invalid BGP marker")
    msg_len, msg_type = struct.unpack_from("!HB", header, 16)
    if msg_len < BGP_HEADER_LEN:
        raise BGPParseError(f"BGP message length {msg_len} < minimum {BGP_HEADER_LEN}")
    body_len = msg_len - BGP_HEADER_LEN
    body = await reader.readexactly(body_len) if body_len > 0 else b""
    return msg_type, body
