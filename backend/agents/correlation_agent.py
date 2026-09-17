"""Evidence Correlation Agent.

Builds an evidence graph linking the entities and events of an incident so an
analyst can click a node and inspect the underlying events. Nodes are typed
(ip / user / host / process / dest / event) and edges express the observed
relationships.
"""
from __future__ import annotations

from ..detection.rules import _is_failed_login, _is_success_login
from .context import IncidentContext


def build_graph(ctx: IncidentContext) -> dict:
    nodes: dict[str, dict] = {}
    edges: list[dict] = []

    def add_node(nid, ntype, label, refs=None):
        if nid not in nodes:
            nodes[nid] = {"id": nid, "type": ntype, "label": label,
                          "event_refs": refs or []}
        elif refs:
            nodes[nid]["event_refs"] = sorted(
                set(nodes[nid]["event_refs"]) | set(refs))

    def add_edge(a, b, rel):
        edges.append({"source": a, "target": b, "relation": rel})

    for ip in ctx.source_ips:
        if ip:
            add_node(f"ip:{ip}", "ip", ip)
    for u in ctx.users:
        if u:
            add_node(f"user:{u}", "user", u)
    for h in ctx.hosts:
        if h:
            add_node(f"host:{h}", "host", h)
    for d in ctx.destination_ips:
        if d:
            add_node(f"dest:{d}", "dest", d)

    seen_edges = set()
    for e in ctx.events:
        eid = e["id"]
        ip = e.get("source_ip")
        user = e.get("user")
        host = e.get("host")
        dest = e.get("destination_ip")
        proc = e.get("process")

        if ip:
            add_node(f"ip:{ip}", "ip", ip, [eid])
        if user:
            add_node(f"user:{user}", "user", user, [eid])
        if host:
            add_node(f"host:{host}", "host", host, [eid])
        if dest:
            add_node(f"dest:{dest}", "dest", dest, [eid])
        if proc:
            add_node(f"proc:{proc}", "process", proc, [eid])

        rel = ("failed-auth" if _is_failed_login(e)
               else "auth" if _is_success_login(e) else "activity")

        def link(a, b, r):
            key = (a, b, r)
            if a in nodes and b in nodes and key not in seen_edges:
                seen_edges.add(key)
                add_edge(a, b, r)

        if ip and user:
            link(f"ip:{ip}", f"user:{user}", rel)
        if ip and host:
            link(f"ip:{ip}", f"host:{host}", rel)
        if user and host:
            link(f"user:{user}", f"host:{host}", "session")
        if host and proc:
            link(f"host:{host}", f"proc:{proc}", "executed")
        if host and dest:
            link(f"host:{host}", f"dest:{dest}", "connection")
        if proc and dest:
            link(f"proc:{proc}", f"dest:{dest}", "outbound")

    return {"nodes": list(nodes.values()), "edges": edges}


def assess(ctx: IncidentContext) -> dict:
    graph = build_graph(ctx)
    node_count = len(graph["nodes"])
    edge_count = len(graph["edges"])
    # A well-connected graph across multiple entity types => stronger correlation.
    types = {n["type"] for n in graph["nodes"]}
    connectedness = min(1.0, edge_count / max(node_count, 1))
    conf = min(0.95, 0.4 + 0.1 * len(types) + 0.3 * connectedness)

    verdict = ("Strongly correlated multi-stage activity"
               if edge_count >= 4 and len(types) >= 3
               else "Related activity correlated"
               if edge_count >= 1 else "Isolated activity")

    return {
        "agent": "Evidence Correlation Agent",
        "verdict": verdict,
        "confidence": round(conf, 2),
        "rationale": (f"Evidence graph: {node_count} nodes across "
                      f"{len(types)} entity types, {edge_count} relationships."),
        "evidence_refs": [],
        "graph": graph,
    }
