"""NetworkX-based topology graph.

Maintains three dictionaries of topology objects keyed by their unique keys,
and a NetworkX DiGraph for path/neighbour queries.
"""

from __future__ import annotations

import threading
import time
from typing import Any

import networkx as nx

from .models import LinkInfo, NodeInfo, PrefixInfo, TopologySnapshot, TopologyStats


class TopologyGraph:
    """Thread-safe container for the complete BGP-LS topology."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._nodes: dict[str, NodeInfo] = {}
        self._links: dict[str, LinkInfo] = {}
        self._prefixes: dict[str, PrefixInfo] = {}
        self._graph = nx.DiGraph()
        self._start_time = time.time()

        # Change callbacks (async): called after each modification batch
        self._change_callbacks: list[Any] = []

    # ------------------------------------------------------------------
    # Mutation API
    # ------------------------------------------------------------------

    def upsert_node(self, node: NodeInfo) -> bool:
        """Insert or update a node. Returns True if this was a new node."""
        with self._lock:
            is_new = node.node_key not in self._nodes
            node.last_updated = time.time()
            if is_new:
                node.first_seen = node.last_updated
            self._nodes[node.node_key] = node
            if not self._graph.has_node(node.node_key):
                self._graph.add_node(node.node_key)
            # Store label for graph visualization
            label = node.node_name or node.igp_router_id or node.node_key
            self._graph.nodes[node.node_key]["label"] = label
            self._graph.nodes[node.node_key]["protocol"] = node.protocol_name
            return is_new

    def upsert_link(self, link: LinkInfo) -> bool:
        """Insert or update a directed link. Returns True if this was a new link."""
        with self._lock:
            is_new = link.link_key not in self._links
            link.last_updated = time.time()
            if is_new:
                link.first_seen = link.last_updated
            self._links[link.link_key] = link
            # Ensure nodes exist in the graph (may arrive before NODE NLRI)
            if not self._graph.has_node(link.local_node_key):
                self._graph.add_node(link.local_node_key)
            if not self._graph.has_node(link.remote_node_key):
                self._graph.add_node(link.remote_node_key)
            self._graph.add_edge(
                link.local_node_key,
                link.remote_node_key,
                key=link.link_key,
                igp_metric=link.igp_metric,
                te_metric=link.te_metric,
            )
            return is_new

    def upsert_prefix(self, prefix: PrefixInfo) -> bool:
        """Insert or update a prefix. Returns True if this was a new prefix."""
        with self._lock:
            is_new = prefix.prefix_key not in self._prefixes
            prefix.last_updated = time.time()
            if is_new:
                prefix.first_seen = prefix.last_updated
            self._prefixes[prefix.prefix_key] = prefix
            return is_new

    def remove_node(self, node_key: str) -> bool:
        with self._lock:
            if node_key in self._nodes:
                del self._nodes[node_key]
                if self._graph.has_node(node_key):
                    self._graph.remove_node(node_key)
                return True
            return False

    def remove_link(self, link_key: str) -> bool:
        with self._lock:
            link = self._links.pop(link_key, None)
            if link:
                if self._graph.has_edge(link.local_node_key, link.remote_node_key):
                    # May be multiple parallel edges; remove by key attr
                    edges_to_remove = [
                        (u, v)
                        for u, v, data in self._graph.edges(data=True)
                        if data.get("key") == link_key
                    ]
                    for u, v in edges_to_remove:
                        self._graph.remove_edge(u, v)
                return True
            return False

    def remove_prefix(self, prefix_key: str) -> bool:
        with self._lock:
            return self._prefixes.pop(prefix_key, None) is not None

    # ------------------------------------------------------------------
    # Query API
    # ------------------------------------------------------------------

    def get_node(self, node_key: str) -> NodeInfo | None:
        with self._lock:
            return self._nodes.get(node_key)

    def get_link(self, link_key: str) -> LinkInfo | None:
        with self._lock:
            return self._links.get(link_key)

    def get_prefix(self, prefix_key: str) -> PrefixInfo | None:
        with self._lock:
            return self._prefixes.get(prefix_key)

    def get_all_nodes(self) -> list[NodeInfo]:
        with self._lock:
            return list(self._nodes.values())

    def get_all_links(self) -> list[LinkInfo]:
        with self._lock:
            return list(self._links.values())

    def get_all_prefixes(self) -> list[PrefixInfo]:
        with self._lock:
            return list(self._prefixes.values())

    def get_node_by_name(self, name: str) -> NodeInfo | None:
        """Look up a node by hostname (Nokia SROS system name)."""
        with self._lock:
            for node in self._nodes.values():
                if node.node_name and node.node_name.lower() == name.lower():
                    return node
            return None

    def get_node_by_router_id(self, router_id: str) -> list[NodeInfo]:
        """Return all nodes matching a given IGP or BGP router-ID."""
        with self._lock:
            return [
                n for n in self._nodes.values()
                if n.igp_router_id == router_id or n.ipv4_router_id == router_id
            ]

    def get_neighbours(self, node_key: str) -> list[str]:
        """Return direct neighbours (successors in directed graph)."""
        with self._lock:
            return list(self._graph.successors(node_key))

    def get_links_from(self, node_key: str) -> list[LinkInfo]:
        with self._lock:
            return [
                lnk for lnk in self._links.values()
                if lnk.local_node_key == node_key
            ]

    def get_prefixes_for_node(self, node_key: str) -> list[PrefixInfo]:
        with self._lock:
            return [p for p in self._prefixes.values() if p.node_key == node_key]

    def shortest_path(
        self, src_key: str, dst_key: str, weight: str = "igp_metric"
    ) -> list[str] | None:
        """Return the shortest-path node sequence or None if unreachable."""
        with self._lock:
            try:
                return nx.shortest_path(self._graph, src_key, dst_key, weight=weight)
            except (nx.NetworkXNoPath, nx.NodeNotFound):
                return None

    def snapshot(self) -> TopologySnapshot:
        with self._lock:
            nodes = list(self._nodes.values())
            links = list(self._links.values())
            prefixes = list(self._prefixes.values())
        return TopologySnapshot(
            nodes=nodes,
            links=links,
            prefixes=prefixes,
            node_count=len(nodes),
            link_count=len(links),
            prefix_count=len(prefixes),
        )

    def stats(self, peer_count: int = 0) -> TopologyStats:
        with self._lock:
            return TopologyStats(
                node_count=len(self._nodes),
                link_count=len(self._links),
                prefix_count=len(self._prefixes),
                peer_count=peer_count,
                uptime_seconds=time.time() - self._start_time,
            )

    def as_dict(self) -> dict:
        """Return a JSON-serialisable representation of the graph."""
        with self._lock:
            return {
                "nodes": [
                    {
                        "id": n.node_key,
                        "label": n.node_name or n.igp_router_id,
                        "protocol": n.protocol_name,
                        "router_id": n.igp_router_id,
                        "ipv4_router_id": n.ipv4_router_id,
                        "sr_capable": n.sr_capabilities is not None,
                    }
                    for n in self._nodes.values()
                ],
                "edges": [
                    {
                        "source": lnk.local_node_key,
                        "target": lnk.remote_node_key,
                        "igp_metric": lnk.igp_metric,
                        "te_metric": lnk.te_metric,
                        "iface": lnk.ipv4_iface_addr or lnk.ipv6_iface_addr,
                    }
                    for lnk in self._links.values()
                ],
            }
