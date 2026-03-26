"""FastAPI application — REST + WebSocket API for the BGP-LS topology.

Endpoints
---------
GET  /                          Health / summary
GET  /stats                     Topology statistics
GET  /topology                  Full topology snapshot (nodes + links + prefixes)
GET  /topology/graph            Simplified graph dict (for visualisation)
GET  /nodes                     All nodes
GET  /nodes/{node_key}          Single node detail
GET  /nodes/name/{name}         Look up node by hostname (Nokia system name)
GET  /links                     All links
GET  /links/{link_key}          Single link detail
GET  /prefixes                  All prefixes
GET  /prefixes/{prefix_key}     Single prefix detail
GET  /nodes/{node_key}/neighbours  Neighbour node keys
GET  /nodes/{node_key}/links    Links from this node
GET  /nodes/{node_key}/prefixes Prefixes advertised by this node
GET  /path?src=&dst=&weight=    Shortest path between two nodes
GET  /peers                     BGP session status for all peers

WS   /ws                        Real-time topology change events (JSON)
"""

from __future__ import annotations

import asyncio
import json
import time
from typing import Any

from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from loguru import logger
from pydantic import BaseModel

from ..topology.graph import TopologyGraph
from ..topology.models import (
    LinkInfo,
    NodeInfo,
    PrefixInfo,
    TopologySnapshot,
    TopologyStats,
)


# ---------------------------------------------------------------------------
# WebSocket manager
# ---------------------------------------------------------------------------

class _WSManager:
    def __init__(self) -> None:
        self._clients: set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        async with self._lock:
            self._clients.add(ws)
        logger.debug(f"WS client connected ({len(self._clients)} total)")

    async def disconnect(self, ws: WebSocket) -> None:
        async with self._lock:
            self._clients.discard(ws)
        logger.debug(f"WS client disconnected ({len(self._clients)} total)")

    async def broadcast(self, message: dict) -> None:
        if not self._clients:
            return
        data = json.dumps(message)
        dead: list[WebSocket] = []
        for ws in list(self._clients):
            try:
                await ws.send_text(data)
            except Exception:
                dead.append(ws)
        async with self._lock:
            for ws in dead:
                self._clients.discard(ws)


_ws_manager = _WSManager()


# ---------------------------------------------------------------------------
# Application factory
# ---------------------------------------------------------------------------

def create_app(
    graph: TopologyGraph,
    get_peer_states: Any = None,
    start_time: float | None = None,
) -> FastAPI:
    """
    Create and return the FastAPI application.

    Args:
        graph:           The shared TopologyGraph.
        get_peer_states: Callable returning list[dict] of BGP peer state dicts.
        start_time:      Application start timestamp for uptime calculation.
    """
    _start = start_time or time.time()

    app = FastAPI(
        title="BGP-LS Topology Collector",
        description=(
            "Collects and exposes BGP-LS topology information from Nokia SROS routers. "
            "Supports IS-IS, OSPFv2/v3, Segment Routing, Flex-Algorithm, and TE attributes."
        ),
        version="1.0.0",
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ------------------------------------------------------------------
    # WebSocket change-event callback (registered by TopologyManager)
    # ------------------------------------------------------------------

    async def topology_change_cb(event: str, key: str, obj: Any) -> None:
        payload: dict[str, Any] = {"event": event, "key": key}
        if obj is not None:
            if hasattr(obj, "model_dump"):
                payload["data"] = obj.model_dump()
            else:
                payload["data"] = obj
        await _ws_manager.broadcast(payload)

    # Expose so main.py can wire it up
    app.state.topology_change_cb = topology_change_cb
    app.state.graph = graph

    # ------------------------------------------------------------------
    # Routes
    # ------------------------------------------------------------------

    @app.get("/", summary="Health check and summary")
    async def root() -> dict:
        s = graph.stats(peer_count=len(get_peer_states()) if get_peer_states else 0)
        return {
            "status": "ok",
            "uptime_seconds": round(time.time() - _start, 1),
            "nodes": s.node_count,
            "links": s.link_count,
            "prefixes": s.prefix_count,
            "peers": s.peer_count,
        }

    @app.get("/stats", response_model=TopologyStats, summary="Topology statistics")
    async def stats() -> TopologyStats:
        return graph.stats(
            peer_count=len(get_peer_states()) if get_peer_states else 0
        )

    # ---- Topology -------------------------------------------------------

    @app.get(
        "/topology",
        response_model=TopologySnapshot,
        summary="Full topology snapshot",
    )
    async def topology() -> TopologySnapshot:
        return graph.snapshot()

    @app.get("/topology/graph", summary="Graph dict suitable for visualisation")
    async def topology_graph() -> dict:
        return graph.as_dict()

    # ---- Nodes ----------------------------------------------------------

    @app.get("/nodes", response_model=list[NodeInfo], summary="All nodes")
    async def list_nodes(
        protocol: str | None = Query(None, description="Filter by protocol name"),
        sr_capable: bool | None = Query(None, description="Filter SR-capable nodes"),
        name: str | None = Query(None, description="Filter by substring of node name"),
    ) -> list[NodeInfo]:
        nodes = graph.get_all_nodes()
        if protocol:
            nodes = [n for n in nodes if n.protocol_name.lower() == protocol.lower()]
        if sr_capable is not None:
            nodes = [
                n for n in nodes
                if (n.sr_capabilities is not None) == sr_capable
            ]
        if name:
            nodes = [
                n for n in nodes
                if n.node_name and name.lower() in n.node_name.lower()
            ]
        return nodes

    @app.get(
        "/nodes/name/{name}",
        response_model=NodeInfo,
        summary="Look up node by hostname",
    )
    async def get_node_by_name(name: str) -> NodeInfo:
        node = graph.get_node_by_name(name)
        if node is None:
            raise HTTPException(status_code=404, detail=f"Node '{name}' not found")
        return node

    @app.get(
        "/nodes/{node_key:path}",
        response_model=NodeInfo,
        summary="Single node detail",
    )
    async def get_node(node_key: str) -> NodeInfo:
        node = graph.get_node(node_key)
        if node is None:
            raise HTTPException(status_code=404, detail=f"Node '{node_key}' not found")
        return node

    @app.get(
        "/nodes/{node_key:path}/neighbours",
        summary="Direct neighbours of a node",
    )
    async def node_neighbours(node_key: str) -> list[str]:
        if graph.get_node(node_key) is None:
            raise HTTPException(status_code=404, detail="Node not found")
        return graph.get_neighbours(node_key)

    @app.get(
        "/nodes/{node_key:path}/links",
        response_model=list[LinkInfo],
        summary="Links originating from a node",
    )
    async def node_links(node_key: str) -> list[LinkInfo]:
        return graph.get_links_from(node_key)

    @app.get(
        "/nodes/{node_key:path}/prefixes",
        response_model=list[PrefixInfo],
        summary="Prefixes advertised by a node",
    )
    async def node_prefixes(node_key: str) -> list[PrefixInfo]:
        return graph.get_prefixes_for_node(node_key)

    # ---- Links ----------------------------------------------------------

    @app.get("/links", response_model=list[LinkInfo], summary="All links")
    async def list_links(
        protocol: str | None = Query(None),
        has_adj_sid: bool | None = Query(None, description="Filter links with Adj-SID"),
    ) -> list[LinkInfo]:
        links = graph.get_all_links()
        if protocol:
            links = [lnk for lnk in links if lnk.protocol_name.lower() == protocol.lower()]
        if has_adj_sid is not None:
            links = [lnk for lnk in links if bool(lnk.adj_sids) == has_adj_sid]
        return links

    @app.get(
        "/links/{link_key:path}",
        response_model=LinkInfo,
        summary="Single link detail",
    )
    async def get_link(link_key: str) -> LinkInfo:
        link = graph.get_link(link_key)
        if link is None:
            raise HTTPException(status_code=404, detail=f"Link '{link_key}' not found")
        return link

    # ---- Prefixes -------------------------------------------------------

    @app.get("/prefixes", response_model=list[PrefixInfo], summary="All prefixes")
    async def list_prefixes(
        protocol: str | None = Query(None),
        ipv6: bool | None = Query(None, description="True=IPv6 only, False=IPv4 only"),
        has_sid: bool | None = Query(None, description="Filter prefixes with SID"),
    ) -> list[PrefixInfo]:
        prefixes = graph.get_all_prefixes()
        if protocol:
            prefixes = [p for p in prefixes if p.protocol_name.lower() == protocol.lower()]
        if ipv6 is not None:
            prefixes = [p for p in prefixes if p.is_ipv6 == ipv6]
        if has_sid is not None:
            prefixes = [p for p in prefixes if bool(p.prefix_sids) == has_sid]
        return prefixes

    @app.get(
        "/prefixes/{prefix_key:path}",
        response_model=PrefixInfo,
        summary="Single prefix detail",
    )
    async def get_prefix(prefix_key: str) -> PrefixInfo:
        prefix = graph.get_prefix(prefix_key)
        if prefix is None:
            raise HTTPException(status_code=404, detail="Prefix not found")
        return prefix

    # ---- Path computation -----------------------------------------------

    @app.get("/path", summary="Shortest path between two nodes (Dijkstra)")
    async def shortest_path(
        src: str = Query(..., description="Source node key"),
        dst: str = Query(..., description="Destination node key"),
        weight: str = Query(
            "igp_metric",
            description="Edge weight attribute: igp_metric | te_metric",
        ),
    ) -> dict:
        path = graph.shortest_path(src, dst, weight=weight)
        if path is None:
            raise HTTPException(
                status_code=404,
                detail=f"No path from '{src}' to '{dst}'",
            )
        # Enrich with node names
        enriched = []
        for key in path:
            node = graph.get_node(key)
            enriched.append(
                {
                    "key": key,
                    "name": node.node_name if node else None,
                    "router_id": node.igp_router_id if node else None,
                }
            )
        return {"src": src, "dst": dst, "weight": weight, "path": enriched, "hops": len(path) - 1}

    # ---- BGP Peers ------------------------------------------------------

    @app.get("/peers", summary="BGP peer session status")
    async def list_peers() -> list[dict]:
        if get_peer_states:
            return get_peer_states()
        return []

    # ---- WebSocket -------------------------------------------------------

    @app.websocket("/ws")
    async def websocket_endpoint(ws: WebSocket) -> None:
        """
        Real-time topology change events.

        Messages are JSON objects:
          {"event": "<type>", "key": "<object_key>", "data": {...} | null}

        event types: node_add, node_update, node_del,
                     link_add, link_update, link_del,
                     prefix_add, prefix_update, prefix_del
        """
        await _ws_manager.connect(ws)
        # Send current topology snapshot on connect
        snapshot = graph.snapshot()
        await ws.send_text(
            json.dumps({"event": "snapshot", "data": snapshot.model_dump()})
        )
        try:
            while True:
                # Keep connection alive; actual events are pushed via broadcast
                await ws.receive_text()
        except WebSocketDisconnect:
            pass
        finally:
            await _ws_manager.disconnect(ws)

    return app
