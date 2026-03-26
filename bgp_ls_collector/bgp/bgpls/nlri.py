"""BGP-LS NLRI decoding (RFC 7752 §3.2).

Parses Node, Link, IPv4-Prefix and IPv6-Prefix NLRIs from the raw bytes
carried in MP_REACH_NLRI / MP_UNREACH_NLRI (AFI=16388, SAFI=71).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Any

from ..constants import (
    NLRI_NODE, NLRI_LINK, NLRI_IPV4_PREFIX, NLRI_IPV6_PREFIX,
    NLRI_TYPE_NAMES, PROTO_NAMES,
)
from ..messages import BGPParseError
from .tlvs import (
    parse_node_descriptor_tlvs,
    parse_link_descriptor_tlvs,
    parse_prefix_descriptor_tlvs,
)


@dataclass
class NodeNLRI:
    """RFC 7752 §3.2.1 — Node NLRI."""
    nlri_type: int = NLRI_NODE
    protocol_id: int = 0
    protocol_name: str = ""
    identifier: int = 0          # 8-byte topology identifier
    local_node: dict[str, Any] = field(default_factory=dict)

    # Key used for deduplication / lookup in the topology graph
    @property
    def key(self) -> str:
        rid = self.local_node.get("igp_router_id", "") or self.local_node.get("bgp_router_id", "")
        return f"{self.protocol_id}:{self.identifier}:{rid}"


@dataclass
class LinkNLRI:
    """RFC 7752 §3.2.2 — Link NLRI."""
    nlri_type: int = NLRI_LINK
    protocol_id: int = 0
    protocol_name: str = ""
    identifier: int = 0
    local_node: dict[str, Any] = field(default_factory=dict)
    remote_node: dict[str, Any] = field(default_factory=dict)
    link_descriptor: dict[str, Any] = field(default_factory=dict)

    @property
    def local_key(self) -> str:
        rid = self.local_node.get("igp_router_id", "") or self.local_node.get("bgp_router_id", "")
        return f"{self.protocol_id}:{self.identifier}:{rid}"

    @property
    def remote_key(self) -> str:
        rid = self.remote_node.get("igp_router_id", "") or self.remote_node.get("bgp_router_id", "")
        return f"{self.protocol_id}:{self.identifier}:{rid}"

    @property
    def link_key(self) -> str:
        """Unique key for this directed link."""
        ld = self.link_descriptor
        local_id = ld.get("link_local_id", 0)
        remote_id = ld.get("link_remote_id", 0)
        iface = ld.get("ipv4_iface_addr") or ld.get("ipv6_iface_addr", "")
        return f"{self.local_key}→{self.remote_key}:{local_id}:{remote_id}:{iface}"


@dataclass
class PrefixNLRI:
    """RFC 7752 §3.2.3 — IPv4 or IPv6 Prefix NLRI."""
    nlri_type: int = NLRI_IPV4_PREFIX
    protocol_id: int = 0
    protocol_name: str = ""
    identifier: int = 0
    local_node: dict[str, Any] = field(default_factory=dict)
    prefix_descriptor: dict[str, Any] = field(default_factory=dict)

    @property
    def prefix(self) -> str:
        return self.prefix_descriptor.get("ip_reachability", "")

    @property
    def node_key(self) -> str:
        rid = self.local_node.get("igp_router_id", "") or self.local_node.get("bgp_router_id", "")
        return f"{self.protocol_id}:{self.identifier}:{rid}"

    @property
    def prefix_key(self) -> str:
        return f"{self.node_key}:{self.prefix}"


BGPLSNLRIType = NodeNLRI | LinkNLRI | PrefixNLRI


# ---------------------------------------------------------------------------
# Top-level parser
# ---------------------------------------------------------------------------

def parse_bgpls_nlri_stream(data: bytes) -> list[BGPLSNLRIType]:
    """
    Parse a stream of BGP-LS NLRIs from raw bytes (as carried in
    MP_REACH_NLRI or MP_UNREACH_NLRI).

    Returns a list of NodeNLRI / LinkNLRI / PrefixNLRI objects.
    """
    results: list[BGPLSNLRIType] = []
    offset = 0
    while offset + 4 <= len(data):
        nlri_type, nlri_len = struct.unpack_from("!HH", data, offset)
        offset += 4
        nlri_data = data[offset : offset + nlri_len]
        offset += nlri_len

        try:
            nlri = _parse_one_nlri(nlri_type, nlri_data)
            if nlri is not None:
                results.append(nlri)
        except BGPParseError as exc:
            import logging
            logging.getLogger(__name__).warning(
                f"Failed to parse BGP-LS NLRI type={nlri_type}: {exc}"
            )
    return results


def _parse_one_nlri(nlri_type: int, data: bytes) -> BGPLSNLRIType | None:
    """Parse a single BGP-LS NLRI."""
    if len(data) < 9:
        raise BGPParseError(f"BGP-LS NLRI type={nlri_type} too short ({len(data)} bytes)")

    protocol_id = data[0]
    identifier = struct.unpack_from("!Q", data, 1)[0]
    proto_name = PROTO_NAMES.get(protocol_id, f"proto-{protocol_id}")
    rest = data[9:]

    if nlri_type == NLRI_NODE:
        return _parse_node_nlri(protocol_id, proto_name, identifier, rest)
    elif nlri_type == NLRI_LINK:
        return _parse_link_nlri(protocol_id, proto_name, identifier, rest)
    elif nlri_type in (NLRI_IPV4_PREFIX, NLRI_IPV6_PREFIX):
        return _parse_prefix_nlri(nlri_type, protocol_id, proto_name, identifier, rest)
    else:
        return None  # Unsupported NLRI type (e.g., SR Policy)


def _parse_node_nlri(
    protocol_id: int, proto_name: str, identifier: int, data: bytes
) -> NodeNLRI:
    """Parse Node Descriptor TLVs from a Node NLRI."""
    local_node = _extract_node_descriptor(data, protocol_id, "Local Node Descriptor")
    return NodeNLRI(
        protocol_id=protocol_id,
        protocol_name=proto_name,
        identifier=identifier,
        local_node=local_node,
    )


def _parse_link_nlri(
    protocol_id: int, proto_name: str, identifier: int, data: bytes
) -> LinkNLRI:
    """Parse Local/Remote Node Descriptors + Link Descriptors from a Link NLRI."""
    offset = 0
    local_node: dict[str, Any] = {}
    remote_node: dict[str, Any] = {}
    link_descriptor: dict[str, Any] = {}

    while offset + 4 <= len(data):
        t, l = struct.unpack_from("!HH", data, offset)
        offset += 4
        v = data[offset : offset + l]
        offset += l

        if t == 256:  # Local Node Descriptor container TLV
            local_node = parse_node_descriptor_tlvs(v, protocol_id)
        elif t == 257:  # Remote Node Descriptor container TLV
            remote_node = parse_node_descriptor_tlvs(v, protocol_id)
        else:
            # Link descriptor sub-TLVs are packed inline after the node descriptors.
            # Re-parse from the start of the link-descriptor section.
            # We'll collect all remaining bytes as link descriptors.
            link_desc_start = offset - 4 - l  # backtrack
            link_descriptor = parse_link_descriptor_tlvs(data[link_desc_start:])
            break

    # If link_descriptor was not yet set (all TLVs were node descriptors)
    if not link_descriptor:
        # Check if there's any remaining data beyond the node descriptor TLVs
        # that constitutes link-descriptor TLVs (type < 256)
        link_desc_start = _find_link_desc_offset(data)
        if link_desc_start < len(data):
            link_descriptor = parse_link_descriptor_tlvs(data[link_desc_start:])

    return LinkNLRI(
        protocol_id=protocol_id,
        protocol_name=proto_name,
        identifier=identifier,
        local_node=local_node,
        remote_node=remote_node,
        link_descriptor=link_descriptor,
    )


def _parse_prefix_nlri(
    nlri_type: int, protocol_id: int, proto_name: str, identifier: int, data: bytes
) -> PrefixNLRI:
    """Parse Local Node Descriptor + Prefix Descriptor TLVs from a Prefix NLRI."""
    offset = 0
    local_node: dict[str, Any] = {}
    prefix_descriptor: dict[str, Any] = {}

    while offset + 4 <= len(data):
        t, l = struct.unpack_from("!HH", data, offset)
        offset += 4
        v = data[offset : offset + l]
        offset += l

        if t == 256:  # Local Node Descriptor
            local_node = parse_node_descriptor_tlvs(v, protocol_id)
        else:
            # Remaining TLVs are prefix descriptors
            prefix_start = offset - 4 - l
            prefix_descriptor = parse_prefix_descriptor_tlvs(data[prefix_start:])
            break

    return PrefixNLRI(
        nlri_type=nlri_type,
        protocol_id=protocol_id,
        protocol_name=proto_name,
        identifier=identifier,
        local_node=local_node,
        prefix_descriptor=prefix_descriptor,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _extract_node_descriptor(
    data: bytes, protocol_id: int, context: str
) -> dict[str, Any]:
    """
    Find the Local Node Descriptor container TLV (type 256) and
    parse its sub-TLVs.  Falls back to treating *data* as raw sub-TLVs
    if no container TLV is found.
    """
    offset = 0
    while offset + 4 <= len(data):
        t, l = struct.unpack_from("!HH", data, offset)
        offset += 4
        v = data[offset : offset + l]
        offset += l
        if t == 256:
            return parse_node_descriptor_tlvs(v, protocol_id)
    # Fallback: try direct sub-TLV parse
    return parse_node_descriptor_tlvs(data, protocol_id)


def _find_link_desc_offset(data: bytes) -> int:
    """
    Scan TLVs and return offset where link-descriptor TLVs begin
    (i.e., after all node-descriptor container TLVs with type 256/257).
    """
    offset = 0
    while offset + 4 <= len(data):
        t, l = struct.unpack_from("!HH", data, offset)
        if t not in (256, 257):
            return offset
        offset += 4 + l
    return len(data)
