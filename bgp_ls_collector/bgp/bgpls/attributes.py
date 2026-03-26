"""BGP-LS Path Attribute (type 29) parser (RFC 7752 §3.3).

The BGP-LS attribute carries node, link, and prefix attributes in TLV form.
The NLRI type (Node / Link / Prefix) from the same UPDATE determines which
set of attribute TLVs is present.
"""

from __future__ import annotations

import struct
from typing import Any

from .tlvs import (
    parse_node_attr_tlvs,
    parse_link_attr_tlvs,
    parse_prefix_attr_tlvs,
)
from ..constants import NLRI_NODE, NLRI_LINK, NLRI_IPV4_PREFIX, NLRI_IPV6_PREFIX
from ..messages import BGPParseError


def parse_bgpls_attribute(
    raw: bytes, nlri_type: int
) -> dict[str, Any]:
    """
    Parse a BGP-LS attribute (path attribute type 29) according to the
    accompanying NLRI type.

    Args:
        raw:        Raw bytes of the attribute value (after flag/type/length).
        nlri_type:  One of NLRI_NODE, NLRI_LINK, NLRI_IPV4_PREFIX, NLRI_IPV6_PREFIX.

    Returns:
        Dict of parsed attribute fields.
    """
    if nlri_type == NLRI_NODE:
        return parse_node_attr_tlvs(raw)
    elif nlri_type == NLRI_LINK:
        return parse_link_attr_tlvs(raw)
    elif nlri_type in (NLRI_IPV4_PREFIX, NLRI_IPV6_PREFIX):
        return parse_prefix_attr_tlvs(raw)
    else:
        return {"raw": raw.hex()}
