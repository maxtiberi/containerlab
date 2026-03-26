"""Pydantic models for the network topology elements.

All fields that arrive via BGP-LS are stored here; Nokia SROS-specific
extras (Flex-Algo, SR capabilities, etc.) are included as regular dict
fields to accommodate schema evolution without model changes.
"""

from __future__ import annotations

import time
from typing import Any, Optional
from pydantic import BaseModel, Field


class SRGBRange(BaseModel):
    first_label: int
    range_size: int


class SRCapabilities(BaseModel):
    flags: dict[str, bool] = Field(default_factory=dict)
    srgb_ranges: list[SRGBRange] = Field(default_factory=list)


class AdjSID(BaseModel):
    flags: dict[str, bool] = Field(default_factory=dict)
    weight: int = 0
    sid: int = 0


class LanAdjSID(BaseModel):
    flags: dict[str, bool] = Field(default_factory=dict)
    weight: int = 0
    neighbor_id: str = ""
    sid: int = 0


class PrefixSID(BaseModel):
    flags: dict[str, bool] = Field(default_factory=dict)
    algorithm: int = 0
    sid: int = 0


# ---------------------------------------------------------------------------
# Node
# ---------------------------------------------------------------------------

class NodeInfo(BaseModel):
    """A network node as reported by BGP-LS."""

    # Identity
    node_key: str                       # internal unique key
    protocol_id: int
    protocol_name: str
    identifier: int                     # BGP-LS topology identifier
    igp_router_id: str = ""             # IS-IS System-ID or OSPF Router-ID
    bgp_router_id: Optional[str] = None

    # Descriptors
    as_number: Optional[int] = None
    bgp_ls_id: Optional[int] = None
    ospf_area_id: Optional[str] = None
    isis_area_id: Optional[str] = None

    # Node attributes (from BGP-LS Attribute TLV)
    node_name: Optional[str] = None     # hostname string (Nokia SROS: system name)
    ipv4_router_id: Optional[str] = None
    ipv6_router_id: Optional[str] = None
    sr_capabilities: Optional[dict[str, Any]] = None
    sr_algorithms: list[int] = Field(default_factory=list)
    sr_local_block: Optional[dict[str, Any]] = None
    flex_algo_definitions: list[dict[str, Any]] = Field(default_factory=list)
    mt_ids: list[dict[str, Any]] = Field(default_factory=list)
    isis_flags: Optional[dict[str, bool]] = None
    ospf_node_properties: Optional[dict[str, bool]] = None
    node_msd: list[dict[str, Any]] = Field(default_factory=list)
    srms_preference: Optional[int] = None

    # Meta
    advertising_peer: str = ""          # BGP peer IP that sent this
    first_seen: float = Field(default_factory=time.time)
    last_updated: float = Field(default_factory=time.time)
    extra: dict[str, Any] = Field(default_factory=dict)  # Nokia / unknown attrs


# ---------------------------------------------------------------------------
# Link
# ---------------------------------------------------------------------------

class LinkInfo(BaseModel):
    """A directed link (adjacency) as reported by BGP-LS."""

    # Identity
    link_key: str
    protocol_id: int
    protocol_name: str
    identifier: int

    # Endpoints (node keys)
    local_node_key: str
    remote_node_key: str
    local_igp_router_id: str = ""
    remote_igp_router_id: str = ""

    # Link Descriptors
    link_local_id: Optional[int] = None
    link_remote_id: Optional[int] = None
    ipv4_iface_addr: Optional[str] = None
    ipv4_neighbor_addr: Optional[str] = None
    ipv6_iface_addr: Optional[str] = None
    ipv6_neighbor_addr: Optional[str] = None
    mt_ids: list[int] = Field(default_factory=list)

    # Link Attributes (from BGP-LS Attribute TLV)
    ipv4_router_id_local: Optional[str] = None
    ipv6_router_id_local: Optional[str] = None
    ipv4_router_id_remote: Optional[str] = None
    ipv6_router_id_remote: Optional[str] = None
    admin_group: Optional[int] = None           # RFC 2702 bitmask
    extended_admin_group: Optional[str] = None  # RFC 7308 hex
    max_link_bw_bps: Optional[float] = None
    max_reservable_bw_bps: Optional[float] = None
    unreserved_bw_bps: list[float] = Field(default_factory=list)
    te_metric: Optional[int] = None
    igp_metric: Optional[int] = None
    link_protection: Optional[dict[str, bool]] = None
    mpls_protocols: Optional[dict[str, bool]] = None
    srlg: list[int] = Field(default_factory=list)
    link_name: Optional[str] = None
    adj_sids: list[dict[str, Any]] = Field(default_factory=list)
    lan_adj_sids: list[dict[str, Any]] = Field(default_factory=list)

    # Performance metrics (RFC 8570)
    unidir_link_delay_us: Optional[int] = None
    unidir_delay_min_us: Optional[int] = None
    unidir_delay_max_us: Optional[int] = None
    unidir_delay_variation_us: Optional[int] = None
    unidir_link_loss_percent: Optional[float] = None
    unidir_residual_bw_bps: Optional[float] = None
    unidir_available_bw_bps: Optional[float] = None
    unidir_utilized_bw_bps: Optional[float] = None

    # Meta
    advertising_peer: str = ""
    first_seen: float = Field(default_factory=time.time)
    last_updated: float = Field(default_factory=time.time)
    extra: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Prefix
# ---------------------------------------------------------------------------

class PrefixInfo(BaseModel):
    """An IP prefix as reported by BGP-LS."""

    prefix_key: str
    protocol_id: int
    protocol_name: str
    identifier: int
    is_ipv6: bool = False

    # Owning node
    node_key: str
    igp_router_id: str = ""

    # Prefix Descriptor
    prefix: str = ""                    # CIDR notation e.g. "10.0.0.0/24"
    ospf_route_type: Optional[int] = None
    ospf_route_type_name: Optional[str] = None
    mt_ids: list[int] = Field(default_factory=list)

    # Prefix Attributes (from BGP-LS Attribute TLV)
    igp_flags: Optional[dict[str, bool]] = None
    igp_route_tags: list[int] = Field(default_factory=list)
    ext_igp_route_tags: list[int] = Field(default_factory=list)
    prefix_metric: Optional[int] = None
    ospf_forwarding_addr: Optional[str] = None
    prefix_sids: list[dict[str, Any]] = Field(default_factory=list)
    sid_ranges: list[dict[str, Any]] = Field(default_factory=list)
    ipv6_source_router_id: Optional[str] = None
    prefix_attr_flags: Optional[dict[str, bool]] = None

    # Meta
    advertising_peer: str = ""
    first_seen: float = Field(default_factory=time.time)
    last_updated: float = Field(default_factory=time.time)
    extra: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Topology snapshot (returned by API)
# ---------------------------------------------------------------------------

class TopologySnapshot(BaseModel):
    nodes: list[NodeInfo]
    links: list[LinkInfo]
    prefixes: list[PrefixInfo]
    node_count: int
    link_count: int
    prefix_count: int
    generated_at: float = Field(default_factory=time.time)


class TopologyStats(BaseModel):
    node_count: int
    link_count: int
    prefix_count: int
    peer_count: int
    uptime_seconds: float
