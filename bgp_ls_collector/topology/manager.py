"""Topology Manager — processes BGP-LS UPDATE messages and maintains the graph.

This is the core integration point between the BGP session layer and the
topology graph.  For every received UPDATE it:

  1. Parses BGP-LS NLRIs (Node / Link / Prefix).
  2. Extracts the BGP-LS Attribute (type 29) for that NLRI.
  3. Creates or updates NodeInfo / LinkInfo / PrefixInfo objects.
  4. Handles withdrawals (MP_UNREACH_NLRI) by removing objects.
  5. Dispatches change events to registered async callbacks.
"""

from __future__ import annotations

import asyncio
from typing import Any, Callable, Awaitable

from loguru import logger

from ..bgp.bgpls.attributes import parse_bgpls_attribute
from ..bgp.bgpls.nlri import (
    BGPLSNLRIType,
    LinkNLRI,
    NodeNLRI,
    PrefixNLRI,
    parse_bgpls_nlri_stream,
)
from ..bgp.constants import AFI_BGP_LS, NLRI_LINK, NLRI_NODE, NLRI_IPV4_PREFIX, NLRI_IPV6_PREFIX, SAFI_BGPLS
from ..bgp.messages import UpdateMessage
from ..bgp.session import BGPSession
from .graph import TopologyGraph
from .models import LinkInfo, NodeInfo, PrefixInfo


ChangeCallback = Callable[[str, str, Any], Awaitable[None]]
"""Signature: (event_type, object_key, object_or_None)"""


class TopologyManager:
    """
    Processes BGP-LS UPDATE messages and keeps the TopologyGraph current.

    Args:
        graph:          The shared TopologyGraph instance.
        change_cb:      Optional async callback invoked on topology changes.
                        Signature: (event_type, key, obj_or_None)
                        event_type in {"node_add", "node_update", "node_del",
                                       "link_add", "link_update", "link_del",
                                       "prefix_add", "prefix_update", "prefix_del"}
    """

    def __init__(
        self,
        graph: TopologyGraph,
        change_cb: ChangeCallback | None = None,
    ) -> None:
        self.graph = graph
        self._change_cb = change_cb

    # ------------------------------------------------------------------
    # BGP session callback
    # ------------------------------------------------------------------

    async def on_update(self, session: BGPSession, update: UpdateMessage) -> None:
        """
        Called by BGPSession for every received UPDATE message.
        Registered as the update_cb when creating BGPSession instances.
        """
        peer_ip = session.config.neighbor_ip

        # ---- ADVERTISEMENTS (MP_REACH_NLRI) ----
        if update.mp_reach is not None:
            mp = update.mp_reach
            if mp.afi == AFI_BGP_LS and mp.safi == SAFI_BGPLS:
                nlris = parse_bgpls_nlri_stream(mp.nlri_data)
                for nlri in nlris:
                    await self._handle_advertise(nlri, update.bgpls_attr_raw, peer_ip)

        # ---- WITHDRAWALS (MP_UNREACH_NLRI) ----
        if update.mp_unreach is not None:
            mp = update.mp_unreach
            if mp.afi == AFI_BGP_LS and mp.safi == SAFI_BGPLS:
                withdrawn = parse_bgpls_nlri_stream(mp.withdrawn_data)
                for nlri in withdrawn:
                    await self._handle_withdraw(nlri, peer_ip)

    # ------------------------------------------------------------------
    # Advertisement processing
    # ------------------------------------------------------------------

    async def _handle_advertise(
        self,
        nlri: BGPLSNLRIType,
        bgpls_attr_raw: bytes | None,
        peer_ip: str,
    ) -> None:
        if isinstance(nlri, NodeNLRI):
            await self._process_node(nlri, bgpls_attr_raw, peer_ip)
        elif isinstance(nlri, LinkNLRI):
            await self._process_link(nlri, bgpls_attr_raw, peer_ip)
        elif isinstance(nlri, PrefixNLRI):
            await self._process_prefix(nlri, bgpls_attr_raw, peer_ip)

    async def _process_node(
        self, nlri: NodeNLRI, raw_attr: bytes | None, peer_ip: str
    ) -> None:
        attrs: dict[str, Any] = {}
        if raw_attr:
            try:
                attrs = parse_bgpls_attribute(raw_attr, NLRI_NODE)
            except Exception as exc:
                logger.warning(f"[{peer_ip}] Failed to parse Node BGP-LS attr: {exc}")

        node = NodeInfo(
            node_key=nlri.key,
            protocol_id=nlri.protocol_id,
            protocol_name=nlri.protocol_name,
            identifier=nlri.identifier,
            igp_router_id=nlri.local_node.get("igp_router_id", ""),
            bgp_router_id=nlri.local_node.get("bgp_router_id"),
            as_number=nlri.local_node.get("as_number"),
            bgp_ls_id=nlri.local_node.get("bgp_ls_id"),
            ospf_area_id=nlri.local_node.get("ospf_area_id"),
            # Attributes
            node_name=attrs.get("node_name"),
            ipv4_router_id=attrs.get("ipv4_router_id"),
            ipv6_router_id=attrs.get("ipv6_router_id"),
            sr_capabilities=attrs.get("sr_capabilities"),
            sr_algorithms=attrs.get("sr_algorithms", []),
            sr_local_block=attrs.get("sr_local_block"),
            flex_algo_definitions=attrs.get("flex_algo_definitions", []),
            mt_ids=attrs.get("mt_ids", []),
            isis_flags=attrs.get("isis_flags"),
            ospf_node_properties=attrs.get("ospf_node_properties"),
            node_msd=attrs.get("node_msd", []),
            srms_preference=attrs.get("srms_preference"),
            isis_area_id=nlri.local_node.get("igp_router_id"),
            advertising_peer=peer_ip,
            extra={k: v for k, v in attrs.items() if k.startswith("unknown")},
        )
        # Pick up IS-IS Area ID from node attributes if present
        if "isis_area_id" in attrs:
            node.extra["isis_area_id"] = attrs["isis_area_id"]

        is_new = self.graph.upsert_node(node)
        event = "node_add" if is_new else "node_update"
        logger.debug(f"[{peer_ip}] {event}: {node.node_key} name={node.node_name}")
        await self._notify(event, node.node_key, node)

    async def _process_link(
        self, nlri: LinkNLRI, raw_attr: bytes | None, peer_ip: str
    ) -> None:
        attrs: dict[str, Any] = {}
        if raw_attr:
            try:
                attrs = parse_bgpls_attribute(raw_attr, NLRI_LINK)
            except Exception as exc:
                logger.warning(f"[{peer_ip}] Failed to parse Link BGP-LS attr: {exc}")

        ld = nlri.link_descriptor
        link = LinkInfo(
            link_key=nlri.link_key,
            protocol_id=nlri.protocol_id,
            protocol_name=nlri.protocol_name,
            identifier=nlri.identifier,
            local_node_key=nlri.local_key,
            remote_node_key=nlri.remote_key,
            local_igp_router_id=nlri.local_node.get("igp_router_id", ""),
            remote_igp_router_id=nlri.remote_node.get("igp_router_id", ""),
            # Descriptors
            link_local_id=ld.get("link_local_id"),
            link_remote_id=ld.get("link_remote_id"),
            ipv4_iface_addr=ld.get("ipv4_iface_addr"),
            ipv4_neighbor_addr=ld.get("ipv4_neighbor_addr"),
            ipv6_iface_addr=ld.get("ipv6_iface_addr"),
            ipv6_neighbor_addr=ld.get("ipv6_neighbor_addr"),
            mt_ids=ld.get("mt_ids", []),
            # Attributes
            ipv4_router_id_local=attrs.get("ipv4_router_id_local"),
            ipv6_router_id_local=attrs.get("ipv6_router_id_local"),
            ipv4_router_id_remote=attrs.get("ipv4_router_id_remote"),
            ipv6_router_id_remote=attrs.get("ipv6_router_id_remote"),
            admin_group=attrs.get("admin_group"),
            extended_admin_group=attrs.get("extended_admin_group"),
            max_link_bw_bps=attrs.get("max_link_bw_bps"),
            max_reservable_bw_bps=attrs.get("max_reservable_bw_bps"),
            unreserved_bw_bps=attrs.get("unreserved_bw_bps", []),
            te_metric=attrs.get("te_metric"),
            igp_metric=attrs.get("igp_metric"),
            link_protection=attrs.get("link_protection"),
            mpls_protocols=attrs.get("mpls_protocols"),
            srlg=attrs.get("srlg", []),
            link_name=attrs.get("link_name"),
            adj_sids=attrs.get("adj_sids", []),
            lan_adj_sids=attrs.get("lan_adj_sids", []),
            unidir_link_delay_us=attrs.get("unidir_link_delay_us"),
            unidir_delay_min_us=attrs.get("unidir_delay_min_us"),
            unidir_delay_max_us=attrs.get("unidir_delay_max_us"),
            unidir_delay_variation_us=attrs.get("unidir_delay_variation_us"),
            unidir_link_loss_percent=attrs.get("unidir_link_loss_percent"),
            unidir_residual_bw_bps=attrs.get("unidir_residual_bw_bps"),
            unidir_available_bw_bps=attrs.get("unidir_available_bw_bps"),
            unidir_utilized_bw_bps=attrs.get("unidir_utilized_bw_bps"),
            advertising_peer=peer_ip,
            extra={k: v for k, v in attrs.items() if k.startswith("unknown")},
        )
        is_new = self.graph.upsert_link(link)
        event = "link_add" if is_new else "link_update"
        logger.debug(
            f"[{peer_ip}] {event}: {link.local_igp_router_id} → "
            f"{link.remote_igp_router_id} metric={link.igp_metric}"
        )
        await self._notify(event, link.link_key, link)

    async def _process_prefix(
        self, nlri: PrefixNLRI, raw_attr: bytes | None, peer_ip: str
    ) -> None:
        attrs: dict[str, Any] = {}
        if raw_attr:
            try:
                attrs = parse_bgpls_attribute(raw_attr, nlri.nlri_type)
            except Exception as exc:
                logger.warning(f"[{peer_ip}] Failed to parse Prefix BGP-LS attr: {exc}")

        pd = nlri.prefix_descriptor
        prefix = PrefixInfo(
            prefix_key=nlri.prefix_key,
            protocol_id=nlri.protocol_id,
            protocol_name=nlri.protocol_name,
            identifier=nlri.identifier,
            is_ipv6=(nlri.nlri_type == NLRI_IPV6_PREFIX),
            node_key=nlri.node_key,
            igp_router_id=nlri.local_node.get("igp_router_id", ""),
            prefix=pd.get("ip_reachability", ""),
            ospf_route_type=pd.get("ospf_route_type"),
            ospf_route_type_name=pd.get("ospf_route_type_name"),
            mt_ids=pd.get("mt_ids", []),
            # Attributes
            igp_flags=attrs.get("igp_flags"),
            igp_route_tags=attrs.get("igp_route_tags", []),
            ext_igp_route_tags=attrs.get("ext_igp_route_tags", []),
            prefix_metric=attrs.get("prefix_metric"),
            ospf_forwarding_addr=attrs.get("ospf_forwarding_addr"),
            prefix_sids=attrs.get("prefix_sids", []),
            sid_ranges=attrs.get("sid_ranges", []),
            ipv6_source_router_id=attrs.get("ipv6_source_router_id"),
            prefix_attr_flags=attrs.get("prefix_attr_flags"),
            advertising_peer=peer_ip,
            extra={k: v for k, v in attrs.items() if k.startswith("unknown")},
        )
        is_new = self.graph.upsert_prefix(prefix)
        event = "prefix_add" if is_new else "prefix_update"
        logger.debug(f"[{peer_ip}] {event}: {prefix.prefix} on node {prefix.node_key}")
        await self._notify(event, prefix.prefix_key, prefix)

    # ------------------------------------------------------------------
    # Withdrawal processing
    # ------------------------------------------------------------------

    async def _handle_withdraw(self, nlri: BGPLSNLRIType, peer_ip: str) -> None:
        if isinstance(nlri, NodeNLRI):
            removed = self.graph.remove_node(nlri.key)
            if removed:
                logger.info(f"[{peer_ip}] node_del: {nlri.key}")
                await self._notify("node_del", nlri.key, None)
        elif isinstance(nlri, LinkNLRI):
            removed = self.graph.remove_link(nlri.link_key)
            if removed:
                logger.info(f"[{peer_ip}] link_del: {nlri.link_key}")
                await self._notify("link_del", nlri.link_key, None)
        elif isinstance(nlri, PrefixNLRI):
            removed = self.graph.remove_prefix(nlri.prefix_key)
            if removed:
                logger.info(f"[{peer_ip}] prefix_del: {nlri.prefix_key}")
                await self._notify("prefix_del", nlri.prefix_key, None)

    # ------------------------------------------------------------------
    # Notification helper
    # ------------------------------------------------------------------

    async def _notify(self, event: str, key: str, obj: Any) -> None:
        if self._change_cb:
            try:
                await self._change_cb(event, key, obj)
            except Exception as exc:
                logger.warning(f"Change callback error: {exc}")
