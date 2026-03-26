"""Nokia SROS-specific BGP-LS extensions and helpers.

Nokia SROS routers implement the standard BGP-LS RFCs faithfully, but there
are several SROS-specific behaviours and configuration patterns worth noting:

1.  **Node Name** — SROS uses the system name as the BGP-LS Node Name TLV
    (type 1029).  This is the most human-readable identifier.

2.  **Segment Routing** — SROS supports both SR-MPLS (RFC 8571) and SRv6
    (RFC 9252).  SR Capabilities, SR Algorithm, SRLB, and Node/Prefix/Adj
    SIDs are all encoded per standard RFCs.

3.  **Flex-Algorithm** — SROS supports Flex-Algorithm (RFC 9088) for both
    IS-IS and OSPF.  Flex-Algo Definitions (TLV 1039) and per-algorithm
    prefix SIDs (algorithm field in Prefix SID TLV) are supported.

4.  **TE Delay Metrics** — SROS supports RFC 8570 one-way delay measurement
    and exports the values via BGP-LS Link Attribute TLVs 1116-1122.

5.  **EPE (BGP Peer Engineering)** — SROS can export BGP peer SIDs for
    inter-AS SR-TE.

6.  **RSVP-TE LSPs** — SROS can redistribute RSVP-TE LSP information into
    BGP-LS (draft-ietf-idr-te-lsp-distribution).

This module provides:
- SROS-specific TLV type constants (vendor-specific / draft ranges)
- Helper functions to interpret SROS-encoded information
- SROS configuration template generator
"""

from __future__ import annotations

from typing import Any


# ---------------------------------------------------------------------------
# Nokia Vendor-Specific / Draft TLV Types
# ---------------------------------------------------------------------------

# Nokia uses some draft TLV ranges not yet standardised at the time of
# certain SROS releases.  These may overlap with later IANA assignments.
# Always cross-check against the SROS release you are running.

# Draft: BGP-LS SR Policy NLRI / attribute TLVs
# (draft-ietf-idr-te-lsp-distribution)
NOKIA_TE_POLICY_NLRI = 5          # TE Policy NLRI type (IPv4 endpoint)
NOKIA_TE_POLICY_NLRI_V6 = 6       # TE Policy NLRI type (IPv6 endpoint)

# SR Policy attribute TLVs (draft-ietf-idr-segment-routing-te-policy)
NOKIA_POLICY_CANDIDATE_PATH = 1200
NOKIA_POLICY_BINDING_SID = 1201
NOKIA_POLICY_SEGMENT_LIST = 1202
NOKIA_POLICY_SEGMENT = 1203
NOKIA_POLICY_WEIGHT = 1204

# SRv6 SID NLRI (RFC 9252)
NOKIA_SRV6_SID_NLRI = 6          # AFI=16388, SAFI=71, NLRI type 6

# SRv6 attribute TLVs (RFC 9252)
NOKIA_SRV6_ENDPOINT_FUNC = 1250
NOKIA_SRV6_BGP_PeerNodeSID = 1251
NOKIA_SRV6_SID_STRUCT = 1252

# SROS Flex-Algo extended TLVs (RFC 9088)
NOKIA_FA_EXCL_ANY_AFFIN = 1040
NOKIA_FA_INCL_ANY_AFFIN = 1041
NOKIA_FA_INCL_ALL_AFFIN = 1042
NOKIA_FA_DEF_FLAGS = 1043
NOKIA_FA_EXCL_SRLG = 1044
NOKIA_FA_UNSUPPORTED_METRIC = 1045

# Application-Specific Link Attributes (RFC 9104)
NOKIA_APPSPEC_LINK_ATTR = 1122    # draft value used by some SROS releases

# ---------------------------------------------------------------------------
# SROS SR Algorithm values
# ---------------------------------------------------------------------------
SR_ALGO_SPF = 0           # Standard Dijkstra
SR_ALGO_STRICT_SPF = 1    # Strict-SPF (RFC 8402)
SR_ALGO_FLEX_128 = 128    # Flex-Algorithm 128
SR_ALGO_FLEX_MAX = 255    # Flex-Algorithm 255

SR_ALGO_NAMES = {
    SR_ALGO_SPF: "SPF",
    SR_ALGO_STRICT_SPF: "Strict-SPF",
}

def sr_algo_name(algo: int) -> str:
    if algo in SR_ALGO_NAMES:
        return SR_ALGO_NAMES[algo]
    if 128 <= algo <= 255:
        return f"Flex-Algo-{algo}"
    return f"algo-{algo}"


# ---------------------------------------------------------------------------
# SROS-specific interpreters
# ---------------------------------------------------------------------------

def interpret_sros_node(node: dict[str, Any]) -> dict[str, Any]:
    """
    Enrich a NodeInfo.model_dump() with SROS-friendly interpretations.

    Returns a supplementary dict with human-readable fields added.
    """
    out: dict[str, Any] = {}

    if node.get("node_name"):
        out["sros_hostname"] = node["node_name"]

    sr_cap = node.get("sr_capabilities")
    if sr_cap:
        srgb = sr_cap.get("srgb_ranges", [])
        out["srgb_ranges"] = srgb
        if srgb:
            first = srgb[0]
            out["srgb_start"] = first.get("first_label")
            out["srgb_end"] = first.get("first_label", 0) + first.get("range_size", 0) - 1

    sr_algos = node.get("sr_algorithms", [])
    out["sr_algorithm_names"] = [sr_algo_name(a) for a in sr_algos]

    flex_defs = node.get("flex_algo_definitions", [])
    if flex_defs:
        out["flex_algorithms"] = [
            {
                "id": fd.get("flex_algo"),
                "metric": fd.get("metric_type"),
                "calc_type": fd.get("calc_type"),
                "priority": fd.get("priority"),
            }
            for fd in flex_defs
        ]

    srlb = node.get("sr_local_block")
    if srlb:
        ranges = srlb.get("srlb_ranges", [])
        if ranges:
            first = ranges[0]
            out["srlb_start"] = first.get("first_label")
            out["srlb_end"] = first.get("first_label", 0) + first.get("range_size", 0) - 1

    return out


def interpret_sros_link(link: dict[str, Any]) -> dict[str, Any]:
    """
    Enrich a LinkInfo.model_dump() with SROS-friendly interpretations.
    """
    out: dict[str, Any] = {}

    adj_sids = link.get("adj_sids", [])
    if adj_sids:
        out["primary_adj_sid"] = adj_sids[0].get("sid")
        backup_sids = [s["sid"] for s in adj_sids if s.get("flags", {}).get("backup")]
        if backup_sids:
            out["backup_adj_sid"] = backup_sids[0]

    bw = link.get("max_link_bw_bps")
    if bw is not None:
        out["max_link_bw_gbps"] = round(bw / 1e9, 3)

    delay = link.get("unidir_link_delay_us")
    if delay is not None:
        out["unidir_link_delay_ms"] = round(delay / 1000, 3)

    metric = link.get("igp_metric")
    if metric is not None:
        out["igp_metric"] = metric

    admin_group = link.get("admin_group")
    if admin_group is not None:
        out["admin_group_hex"] = f"0x{admin_group:08x}"

    return out


def interpret_sros_prefix(prefix: dict[str, Any]) -> dict[str, Any]:
    """
    Enrich a PrefixInfo.model_dump() with SROS-friendly interpretations.
    """
    out: dict[str, Any] = {}

    sids = prefix.get("prefix_sids", [])
    if sids:
        node_sids = [s for s in sids if s.get("flags", {}).get("node_sid")]
        if node_sids:
            out["node_sid"] = node_sids[0].get("sid")
            out["node_sid_algorithm"] = sr_algo_name(node_sids[0].get("algorithm", 0))
        out["all_prefix_sids"] = [
            {
                "sid": s.get("sid"),
                "algorithm": sr_algo_name(s.get("algorithm", 0)),
                "node_sid": s.get("flags", {}).get("node_sid", False),
                "no_php": s.get("flags", {}).get("no_php", False),
            }
            for s in sids
        ]

    return out


# ---------------------------------------------------------------------------
# SROS configuration template generator
# ---------------------------------------------------------------------------

def generate_sros_bgp_ls_config(
    collector_ip: str,
    collector_as: int,
    local_as: int,
    peer_group_name: str = "BGP-LS-COLLECTOR",
    instance_name: str = "default",
) -> str:
    """
    Generate Nokia SROS CLI snippet to enable BGP-LS export toward
    this collector.

    Args:
        collector_ip:     IP address of the BGP-LS collector (this application).
        collector_as:     AS number of the collector.
        local_as:         Local AS number of the SROS router.
        peer_group_name:  BGP group name to use in config.
        instance_name:    Routing instance / VRF name (usually 'default').

    Returns:
        Multi-line string with SROS MD-CLI configuration.
    """
    return f"""
# Nokia SROS MD-CLI configuration for BGP-LS toward collector
# Generated by bgp-ls-collector

configure {{
    router "{instance_name}" {{
        bgp {{
            group "{peer_group_name}" {{
                type internal
                family {{
                    bgp-ls true
                }}
                local-as {{
                    as-number {local_as}
                }}
                peer-as {collector_as}
                neighbor "{collector_ip}" {{
                    # BGP-LS Collector
                    description "BGP-LS Topology Collector"
                }}
            }}

            # Enable BGP-LS redistribution of IGP topology
            bgp-ls {{
                admin-state enable
                # Export IS-IS Level 1 and Level 2
                isis-export {{
                    level1 true
                    level2 true
                }}
                # Export OSPFv2
                ospf-export {{
                    area all
                }}
                # Include SR topology
                include-sr-topology true
                # Include TE attributes
                include-te-metric true
                include-link-delay true
                include-unreserved-bandwidth true
                include-admin-group true
                include-srlg true
            }}
        }}
    }}
}}
"""


def generate_sros_bgpls_verification() -> str:
    """
    Return SROS MD-CLI verification commands to confirm BGP-LS is working.
    """
    return """
# Verify BGP-LS session and advertisements on SROS

# Check BGP-LS session state
show router bgp summary family bgp-ls

# Check BGP-LS routes being advertised
show router bgp routes bgp-ls

# Check BGP-LS database
show router bgp-ls database

# Check IS-IS topology exported to BGP-LS
show router isis 0 bgp-ls

# Check specific link-state advertisement
show router bgp routes bgp-ls node detail
show router bgp routes bgp-ls link detail
show router bgp routes bgp-ls ipv4-prefix detail
"""
