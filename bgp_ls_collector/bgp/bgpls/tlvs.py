"""BGP-LS TLV (sub-TLV) parsing helpers.

All parse_* functions return a plain dict that can be serialised to JSON.
IEEE 754 bandwidth values are returned as floats (bits/s).
"""

from __future__ import annotations

import ipaddress
import socket
import struct
from typing import Any

from ..constants import (
    # Node descriptor
    ND_AS_NUMBER, ND_BGP_LS_ID, ND_OSPF_AREA_ID, ND_IGP_ROUTER_ID,
    ND_BGP_ROUTER_ID, ND_MEMBER_AS_NUMBER, ND_TYPE_NAMES,
    # Link descriptor
    LD_LINK_LOCAL_REMOTE_IDS, LD_IPV4_IFACE_ADDR, LD_IPV4_NEIGHBOR_ADDR,
    LD_IPV6_IFACE_ADDR, LD_IPV6_NEIGHBOR_ADDR, LD_MT_ID, LD_TYPE_NAMES,
    # Prefix descriptor
    PD_MT_ID, PD_OSPF_ROUTE_TYPE, PD_IP_REACHABILITY, PD_TYPE_NAMES,
    OSPF_ROUTE_TYPE_NAMES,
    # Node attrs
    NA_MT_IDS, NA_OSPF_NODE_PROPS, NA_ISIS_AREA_ID,
    NA_IPV4_ROUTER_ID_LOCAL, NA_IPV6_ROUTER_ID_LOCAL,
    NA_NODE_NAME, NA_ISIS_FLAGS, NA_OPAQUE_NODE, NA_NODE_MSD,
    NA_SR_CAPABILITIES, NA_SR_ALGORITHM, NA_SR_LOCAL_BLOCK,
    NA_SRMS_PREFERENCE, NA_FLEX_ALGO_DEF, NA_FLEX_ALGO_EXCL_ANY,
    NA_TYPE_NAMES,
    # Link attrs
    LA_IPV4_ROUTER_ID_LOCAL, LA_IPV6_ROUTER_ID_LOCAL,
    LA_IPV4_ROUTER_ID_REMOTE, LA_IPV6_ROUTER_ID_REMOTE,
    LA_ADMIN_GROUP, LA_MAX_LINK_BW, LA_MAX_RESERV_BW, LA_UNRESERVED_BW,
    LA_TE_DEFAULT_METRIC, LA_LINK_PROT_TYPE, LA_MPLS_PROTO_MASK,
    LA_IGP_METRIC, LA_SRLG, LA_OPAQUE_LINK, LA_LINK_NAME,
    LA_ADJ_SID, LA_LAN_ADJ_SID,
    LA_UNIDIR_LINK_DELAY, LA_UNIDIR_DELAY_MIN_MAX, LA_UNIDIR_DELAY_VAR,
    LA_UNIDIR_LINK_LOSS, LA_UNIDIR_RESIDUAL_BW, LA_UNIDIR_AVAIL_BW,
    LA_UNIDIR_UTIL_BW, LA_EXT_ADMIN_GROUP, LA_TYPE_NAMES,
    # Prefix attrs
    PRA_IGP_FLAGS, PRA_IGP_ROUTE_TAG, PRA_EXT_IGP_ROUTE_TAG,
    PRA_PREFIX_METRIC, PRA_OSPF_FWD_ADDR, PRA_OPAQUE_PREFIX,
    PRA_PREFIX_SID, PRA_RANGE, PRA_IPV6_SRC_ROUTER_ID,
    PRA_PREFIX_ATTR_FLAGS, PRA_TYPE_NAMES,
    # SR flags
    ADJ_SID_FLAG_F, ADJ_SID_FLAG_B, ADJ_SID_FLAG_V, ADJ_SID_FLAG_L,
    ADJ_SID_FLAG_S, ADJ_SID_FLAG_P,
    PFX_SID_FLAG_R, PFX_SID_FLAG_N, PFX_SID_FLAG_P as PFX_NO_PHP,
    PFX_SID_FLAG_E, PFX_SID_FLAG_V as PFX_SID_VALUE, PFX_SID_FLAG_L as PFX_SID_LOCAL,
    # MT names
    MT_NAMES,
    # Proto names
    PROTO_ISIS_L1, PROTO_ISIS_L2,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ip4(b: bytes) -> str:
    return socket.inet_ntoa(b)


def _ip6(b: bytes) -> str:
    return str(ipaddress.IPv6Address(b))


def _ieee_float(b: bytes) -> float:
    return struct.unpack("!f", b)[0]


def _parse_label_or_index(flags: int, data: bytes, offset: int) -> tuple[int, int]:
    """
    SR SIDs are either 3-byte label (value flag set) or 4-byte index.
    Returns (sid_value, new_offset).
    """
    if flags & 0x20:  # V flag — 3-byte label
        val = struct.unpack_from("!I", b"\x00" + data[offset:offset + 3])[0]
        return val, offset + 3
    else:             # 4-byte index
        val = struct.unpack_from("!I", data, offset)[0]
        return val, offset + 4


def _parse_srgb_ranges(data: bytes) -> list[dict]:
    """Parse one or more SRGB range entries (RFC 8571 §2.1)."""
    ranges = []
    offset = 0
    while offset + 6 <= len(data):
        # Range size (3 bytes) + SID/Label sub-TLV (2+1+3 = 6 bytes minimum)
        range_size = struct.unpack_from("!I", b"\x00" + data[offset:offset + 3])[0]
        offset += 3
        # Sub-TLV: type (2) + length (2) + value
        if offset + 4 > len(data):
            break
        sub_type, sub_len = struct.unpack_from("!HH", data, offset)
        offset += 4
        sub_val = data[offset:offset + sub_len]
        offset += sub_len
        if sub_len == 3:
            label = struct.unpack_from("!I", b"\x00" + sub_val)[0]
        else:
            label = struct.unpack_from("!I", sub_val)[0]
        ranges.append({"range_size": range_size, "first_label": label})
    return ranges


# ---------------------------------------------------------------------------
# IGP Router-ID interpretation
# ---------------------------------------------------------------------------

def format_igp_router_id(proto: int, data: bytes) -> str:
    """Format IGP Router-ID based on protocol."""
    n = len(data)
    if proto in (PROTO_ISIS_L1, PROTO_ISIS_L2):
        # IS-IS: 6-byte System-ID or 7-byte (System-ID + pseudonode-ID)
        if n == 6:
            return ":".join(f"{b:02x}" for b in data)
        elif n == 7:
            sys_id = ":".join(f"{b:02x}" for b in data[:6])
            return f"{sys_id}.{data[6]:02x}"
        else:
            return data.hex()
    else:
        # OSPF / others: 4-byte Router-ID
        if n == 4:
            return _ip4(data)
        elif n == 8:
            # OSPF pseudonode: 4-byte router-id + 4-byte interface
            return f"{_ip4(data[:4])}/{_ip4(data[4:])}"
        return data.hex()


# ---------------------------------------------------------------------------
# Node Descriptor TLV parsers
# ---------------------------------------------------------------------------

def parse_node_descriptor_tlvs(data: bytes, proto: int) -> dict[str, Any]:
    """Parse all sub-TLVs in a Node Descriptor field."""
    result: dict[str, Any] = {}
    offset = 0
    while offset + 4 <= len(data):
        t, l = struct.unpack_from("!HH", data, offset)
        offset += 4
        v = data[offset:offset + l]
        offset += l

        if t == ND_AS_NUMBER and l == 4:
            result["as_number"] = struct.unpack("!I", v)[0]
        elif t == ND_BGP_LS_ID and l == 4:
            result["bgp_ls_id"] = struct.unpack("!I", v)[0]
        elif t == ND_OSPF_AREA_ID and l == 4:
            result["ospf_area_id"] = _ip4(v)
        elif t == ND_IGP_ROUTER_ID:
            result["igp_router_id"] = format_igp_router_id(proto, v)
            result["igp_router_id_raw"] = v.hex()
        elif t == ND_BGP_ROUTER_ID and l == 4:
            result["bgp_router_id"] = _ip4(v)
        elif t == ND_MEMBER_AS_NUMBER and l == 4:
            result["member_as"] = struct.unpack("!I", v)[0]
        else:
            result.setdefault("unknown", {})[t] = v.hex()
    return result


# ---------------------------------------------------------------------------
# Link Descriptor TLV parsers
# ---------------------------------------------------------------------------

def parse_link_descriptor_tlvs(data: bytes) -> dict[str, Any]:
    result: dict[str, Any] = {}
    offset = 0
    while offset + 4 <= len(data):
        t, l = struct.unpack_from("!HH", data, offset)
        offset += 4
        v = data[offset:offset + l]
        offset += l

        if t == LD_LINK_LOCAL_REMOTE_IDS and l == 8:
            result["link_local_id"] = struct.unpack_from("!I", v, 0)[0]
            result["link_remote_id"] = struct.unpack_from("!I", v, 4)[0]
        elif t == LD_IPV4_IFACE_ADDR and l == 4:
            result["ipv4_iface_addr"] = _ip4(v)
        elif t == LD_IPV4_NEIGHBOR_ADDR and l == 4:
            result["ipv4_neighbor_addr"] = _ip4(v)
        elif t == LD_IPV6_IFACE_ADDR and l == 16:
            result["ipv6_iface_addr"] = _ip6(v)
        elif t == LD_IPV6_NEIGHBOR_ADDR and l == 16:
            result["ipv6_neighbor_addr"] = _ip6(v)
        elif t == LD_MT_ID:
            result["mt_ids"] = [
                struct.unpack_from("!H", v, i)[0] & 0x0FFF
                for i in range(0, l, 2)
            ]
        else:
            result.setdefault("unknown", {})[t] = v.hex()
    return result


# ---------------------------------------------------------------------------
# Prefix Descriptor TLV parsers
# ---------------------------------------------------------------------------

def parse_prefix_descriptor_tlvs(data: bytes) -> dict[str, Any]:
    result: dict[str, Any] = {}
    offset = 0
    while offset + 4 <= len(data):
        t, l = struct.unpack_from("!HH", data, offset)
        offset += 4
        v = data[offset:offset + l]
        offset += l

        if t == PD_MT_ID:
            result["mt_ids"] = [
                struct.unpack_from("!H", v, i)[0] & 0x0FFF
                for i in range(0, l, 2)
            ]
        elif t == PD_OSPF_ROUTE_TYPE and l == 1:
            result["ospf_route_type"] = v[0]
            result["ospf_route_type_name"] = OSPF_ROUTE_TYPE_NAMES.get(v[0], str(v[0]))
        elif t == PD_IP_REACHABILITY:
            prefix_len = v[0]
            # Remaining bytes are the prefix (packed, not padded)
            nbytes = (prefix_len + 7) // 8
            prefix_bytes = v[1:1 + nbytes]
            if l <= 5:  # IPv4: prefix-len + up to 4 bytes
                padded = prefix_bytes.ljust(4, b"\x00")
                result["ip_reachability"] = f"{_ip4(padded)}/{prefix_len}"
            else:       # IPv6
                padded = prefix_bytes.ljust(16, b"\x00")
                result["ip_reachability"] = f"{_ip6(padded)}/{prefix_len}"
        else:
            result.setdefault("unknown", {})[t] = v.hex()
    return result


# ---------------------------------------------------------------------------
# Node Attribute TLV parsers
# ---------------------------------------------------------------------------

def parse_node_attr_tlvs(data: bytes) -> dict[str, Any]:
    """Parse all TLVs inside a BGP-LS attribute (type 29) for a Node NLRI."""
    result: dict[str, Any] = {}
    offset = 0
    while offset + 4 <= len(data):
        t, l = struct.unpack_from("!HH", data, offset)
        offset += 4
        v = data[offset:offset + l]
        offset += l

        if t == NA_MT_IDS:
            result["mt_ids"] = [
                {"id": struct.unpack_from("!H", v, i)[0] & 0x0FFF,
                 "name": MT_NAMES.get(struct.unpack_from("!H", v, i)[0] & 0x0FFF, "unknown")}
                for i in range(0, l, 2)
            ]
        elif t == NA_OSPF_NODE_PROPS and l >= 1:
            result["ospf_node_properties"] = {
                "external_bit": bool(v[0] & 0x80),
                "asbr_bit": bool(v[0] & 0x40),
            }
        elif t == NA_ISIS_AREA_ID:
            result["isis_area_id"] = v.hex()
        elif t == NA_IPV4_ROUTER_ID_LOCAL and l == 4:
            result["ipv4_router_id"] = _ip4(v)
        elif t == NA_IPV6_ROUTER_ID_LOCAL and l == 16:
            result["ipv6_router_id"] = _ip6(v)
        elif t == NA_NODE_NAME:
            result["node_name"] = v.decode("utf-8", errors="replace")
        elif t == NA_ISIS_FLAGS and l >= 1:
            result["isis_flags"] = {
                "overload": bool(v[0] & 0x80),
                "attached": bool(v[0] & 0x40),
                "external_routes": bool(v[0] & 0x20),
                "p_flag": bool(v[0] & 0x10),
            }
        elif t == NA_SR_CAPABILITIES:
            result["sr_capabilities"] = _parse_sr_capabilities(v)
        elif t == NA_SR_ALGORITHM:
            result["sr_algorithms"] = list(v)
        elif t == NA_SR_LOCAL_BLOCK:
            result["sr_local_block"] = _parse_srlb(v)
        elif t == NA_SRMS_PREFERENCE and l >= 1:
            result["srms_preference"] = v[0]
        elif t == NA_FLEX_ALGO_DEF:
            result.setdefault("flex_algo_definitions", []).append(
                _parse_flex_algo_def(v)
            )
        elif t == NA_NODE_MSD:
            result["node_msd"] = _parse_msd(v)
        else:
            result.setdefault("unknown_node_attrs", {})[t] = v.hex()
    return result


def _parse_sr_capabilities(data: bytes) -> dict[str, Any]:
    if len(data) < 2:
        return {}
    flags = data[0]
    # data[1] is reserved
    ranges = _parse_srgb_ranges(data[2:])
    return {
        "flags": {
            "ipv4": bool(flags & 0x80),
            "ipv6": bool(flags & 0x40),
        },
        "srgb_ranges": ranges,
    }


def _parse_srlb(data: bytes) -> dict[str, Any]:
    if len(data) < 2:
        return {}
    flags = data[0]
    ranges = _parse_srgb_ranges(data[2:])
    return {"flags": flags, "srlb_ranges": ranges}


def _parse_flex_algo_def(data: bytes) -> dict[str, Any]:
    if len(data) < 4:
        return {}
    flex_algo = data[0]
    metric_type = data[1]
    calc_type = data[2]
    priority = data[3]
    metric_names = {0: "IGP Metric", 1: "Min Unidirectional Link Delay", 2: "TE Default Metric"}
    return {
        "flex_algo": flex_algo,
        "metric_type": metric_names.get(metric_type, str(metric_type)),
        "calc_type": calc_type,
        "priority": priority,
    }


def _parse_msd(data: bytes) -> list[dict]:
    msds = []
    for i in range(0, len(data) - 1, 2):
        msds.append({"msd_type": data[i], "msd_value": data[i + 1]})
    return msds


# ---------------------------------------------------------------------------
# Link Attribute TLV parsers
# ---------------------------------------------------------------------------

def parse_link_attr_tlvs(data: bytes) -> dict[str, Any]:
    """Parse all TLVs inside a BGP-LS attribute (type 29) for a Link NLRI."""
    result: dict[str, Any] = {}
    offset = 0
    while offset + 4 <= len(data):
        t, l = struct.unpack_from("!HH", data, offset)
        offset += 4
        v = data[offset:offset + l]
        offset += l

        if t == LA_IPV4_ROUTER_ID_LOCAL and l == 4:
            result["ipv4_router_id_local"] = _ip4(v)
        elif t == LA_IPV6_ROUTER_ID_LOCAL and l == 16:
            result["ipv6_router_id_local"] = _ip6(v)
        elif t == LA_IPV4_ROUTER_ID_REMOTE and l == 4:
            result["ipv4_router_id_remote"] = _ip4(v)
        elif t == LA_IPV6_ROUTER_ID_REMOTE and l == 16:
            result["ipv6_router_id_remote"] = _ip6(v)
        elif t == LA_ADMIN_GROUP and l == 4:
            result["admin_group"] = struct.unpack("!I", v)[0]
        elif t == LA_MAX_LINK_BW and l == 4:
            result["max_link_bw_bps"] = _ieee_float(v)
        elif t == LA_MAX_RESERV_BW and l == 4:
            result["max_reservable_bw_bps"] = _ieee_float(v)
        elif t == LA_UNRESERVED_BW and l == 32:
            result["unreserved_bw_bps"] = [
                _ieee_float(v[i * 4:(i + 1) * 4]) for i in range(8)
            ]
        elif t == LA_TE_DEFAULT_METRIC and l >= 3:
            # RFC says 4 bytes but some implementations send 3
            val = int.from_bytes(v[:4] if l >= 4 else b"\x00" + v[:3], "big")
            result["te_metric"] = val
        elif t == LA_LINK_PROT_TYPE and l >= 1:
            result["link_protection"] = _parse_link_protection(v[0])
        elif t == LA_MPLS_PROTO_MASK and l >= 1:
            result["mpls_protocols"] = {
                "ldp": bool(v[0] & 0x80),
                "rsvp_te": bool(v[0] & 0x40),
                "sr_te": bool(v[0] & 0x20),
            }
        elif t == LA_IGP_METRIC:
            # IS-IS: 3 bytes; OSPF: 4 bytes (but RFC allows variable)
            result["igp_metric"] = int.from_bytes(v[:min(l, 4)], "big")
        elif t == LA_SRLG:
            result["srlg"] = [
                struct.unpack_from("!I", v, i)[0]
                for i in range(0, l - 3, 4)
            ]
        elif t == LA_LINK_NAME:
            result["link_name"] = v.decode("utf-8", errors="replace")
        elif t == LA_ADJ_SID:
            result.setdefault("adj_sids", []).append(_parse_adj_sid(v))
        elif t == LA_LAN_ADJ_SID:
            result.setdefault("lan_adj_sids", []).append(_parse_lan_adj_sid(v))
        elif t == LA_UNIDIR_LINK_DELAY and l == 4:
            flags = (struct.unpack("!I", v)[0] >> 24) & 0xFF
            delay_us = struct.unpack("!I", v)[0] & 0x00FFFFFF
            result["unidir_link_delay_us"] = delay_us
            result["unidir_link_delay_anomalous"] = bool(flags & 0x80)
        elif t == LA_UNIDIR_DELAY_MIN_MAX and l == 8:
            min_d = struct.unpack_from("!I", v, 0)[0] & 0x00FFFFFF
            max_d = struct.unpack_from("!I", v, 4)[0] & 0x00FFFFFF
            result["unidir_delay_min_us"] = min_d
            result["unidir_delay_max_us"] = max_d
        elif t == LA_UNIDIR_DELAY_VAR and l == 4:
            result["unidir_delay_variation_us"] = struct.unpack("!I", v)[0] & 0x00FFFFFF
        elif t == LA_UNIDIR_LINK_LOSS and l == 4:
            result["unidir_link_loss_percent"] = (
                (struct.unpack("!I", v)[0] & 0x00FFFFFF) * 0.000003
            )
        elif t == LA_UNIDIR_RESIDUAL_BW and l == 4:
            result["unidir_residual_bw_bps"] = _ieee_float(v)
        elif t == LA_UNIDIR_AVAIL_BW and l == 4:
            result["unidir_available_bw_bps"] = _ieee_float(v)
        elif t == LA_UNIDIR_UTIL_BW and l == 4:
            result["unidir_utilized_bw_bps"] = _ieee_float(v)
        elif t == LA_EXT_ADMIN_GROUP:
            result["extended_admin_group"] = v.hex()
        else:
            result.setdefault("unknown_link_attrs", {})[t] = v.hex()
    return result


def _parse_link_protection(byte: int) -> dict[str, bool]:
    return {
        "extra_traffic": bool(byte & 0x01),
        "unprotected": bool(byte & 0x02),
        "shared": bool(byte & 0x04),
        "dedicated_1_1": bool(byte & 0x08),
        "dedicated_1_plus_1": bool(byte & 0x10),
        "enhanced": bool(byte & 0x20),
    }


def _parse_adj_sid(data: bytes) -> dict[str, Any]:
    if len(data) < 7:
        return {"raw": data.hex()}
    flags = data[0]
    weight = data[1]
    # data[2:4] reserved
    sid_data = data[4:]
    if flags & ADJ_SID_FLAG_V:  # 3-byte label
        sid = struct.unpack_from("!I", b"\x00" + sid_data[:3])[0] if len(sid_data) >= 3 else 0
    else:                       # 4-byte index
        sid = struct.unpack_from("!I", sid_data[:4])[0] if len(sid_data) >= 4 else 0
    return {
        "flags": {
            "family_ipv6": bool(flags & ADJ_SID_FLAG_F),
            "backup": bool(flags & ADJ_SID_FLAG_B),
            "value": bool(flags & ADJ_SID_FLAG_V),
            "local": bool(flags & ADJ_SID_FLAG_L),
            "set": bool(flags & ADJ_SID_FLAG_S),
            "persistent": bool(flags & ADJ_SID_FLAG_P),
        },
        "weight": weight,
        "sid": sid,
    }


def _parse_lan_adj_sid(data: bytes) -> dict[str, Any]:
    if len(data) < 11:
        return {"raw": data.hex()}
    flags = data[0]
    weight = data[1]
    # data[2:4] reserved
    # System-ID (6 bytes) or BGP Router-ID (4 bytes) depending on protocol
    neighbor_id = data[4:10].hex()
    sid_data = data[10:]
    if flags & ADJ_SID_FLAG_V:
        sid = struct.unpack_from("!I", b"\x00" + sid_data[:3])[0] if len(sid_data) >= 3 else 0
    else:
        sid = struct.unpack_from("!I", sid_data[:4])[0] if len(sid_data) >= 4 else 0
    return {
        "flags": {
            "family_ipv6": bool(flags & ADJ_SID_FLAG_F),
            "backup": bool(flags & ADJ_SID_FLAG_B),
            "value": bool(flags & ADJ_SID_FLAG_V),
            "local": bool(flags & ADJ_SID_FLAG_L),
            "set": bool(flags & ADJ_SID_FLAG_S),
            "persistent": bool(flags & ADJ_SID_FLAG_P),
        },
        "weight": weight,
        "neighbor_id": neighbor_id,
        "sid": sid,
    }


# ---------------------------------------------------------------------------
# Prefix Attribute TLV parsers
# ---------------------------------------------------------------------------

def parse_prefix_attr_tlvs(data: bytes) -> dict[str, Any]:
    """Parse all TLVs inside a BGP-LS attribute (type 29) for a Prefix NLRI."""
    result: dict[str, Any] = {}
    offset = 0
    while offset + 4 <= len(data):
        t, l = struct.unpack_from("!HH", data, offset)
        offset += 4
        v = data[offset:offset + l]
        offset += l

        if t == PRA_IGP_FLAGS and l >= 1:
            result["igp_flags"] = {
                "down": bool(v[0] & 0x80),          # IS-IS up/down
                "no_unicast": bool(v[0] & 0x40),     # OSPF
                "local_addr": bool(v[0] & 0x20),     # OSPF
                "propagate_nssa": bool(v[0] & 0x10), # OSPF
            }
        elif t == PRA_IGP_ROUTE_TAG:
            result["igp_route_tags"] = [
                struct.unpack_from("!I", v, i)[0]
                for i in range(0, l - 3, 4)
            ]
        elif t == PRA_EXT_IGP_ROUTE_TAG:
            result["ext_igp_route_tags"] = [
                struct.unpack_from("!Q", v, i)[0]
                for i in range(0, l - 7, 8)
            ]
        elif t == PRA_PREFIX_METRIC and l == 4:
            result["prefix_metric"] = struct.unpack("!I", v)[0]
        elif t == PRA_OSPF_FWD_ADDR:
            if l == 4:
                result["ospf_forwarding_addr"] = _ip4(v)
            elif l == 16:
                result["ospf_forwarding_addr"] = _ip6(v)
        elif t == PRA_PREFIX_SID:
            result.setdefault("prefix_sids", []).append(_parse_prefix_sid(v))
        elif t == PRA_RANGE:
            result.setdefault("sid_ranges", []).append(_parse_sid_range(v))
        elif t == PRA_IPV6_SRC_ROUTER_ID and l == 16:
            result["ipv6_source_router_id"] = _ip6(v)
        elif t == PRA_PREFIX_ATTR_FLAGS and l >= 1:
            result["prefix_attr_flags"] = {
                "x_flag": bool(v[0] & 0x80),
                "r_flag": bool(v[0] & 0x40),
                "n_flag": bool(v[0] & 0x20),
                "e_flag": bool(v[0] & 0x10),
            }
        else:
            result.setdefault("unknown_prefix_attrs", {})[t] = v.hex()
    return result


def _parse_prefix_sid(data: bytes) -> dict[str, Any]:
    if len(data) < 7:
        return {"raw": data.hex()}
    flags = data[0]
    algorithm = data[1]
    # data[2:4] reserved
    sid_data = data[4:]
    if flags & PFX_SID_VALUE:  # 3-byte label
        sid = struct.unpack_from("!I", b"\x00" + sid_data[:3])[0] if len(sid_data) >= 3 else 0
    else:                      # 4-byte index
        sid = struct.unpack_from("!I", sid_data[:4])[0] if len(sid_data) >= 4 else 0
    return {
        "flags": {
            "readvertisement": bool(flags & PFX_SID_FLAG_R),
            "node_sid": bool(flags & PFX_SID_FLAG_N),
            "no_php": bool(flags & PFX_NO_PHP),
            "explicit_null": bool(flags & PFX_SID_FLAG_E),
            "value": bool(flags & PFX_SID_VALUE),
            "local": bool(flags & PFX_SID_LOCAL),
        },
        "algorithm": algorithm,
        "sid": sid,
    }


def _parse_sid_range(data: bytes) -> dict[str, Any]:
    if len(data) < 3:
        return {"raw": data.hex()}
    range_size = struct.unpack_from("!I", b"\x00" + data[:3])[0]
    ranges = _parse_srgb_ranges(data[3:]) if len(data) > 3 else []
    return {"range_size": range_size, "ranges": ranges}
