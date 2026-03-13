"""
Architecture graph construction from various sources:
  - Manual JSON definition
  - Kubernetes cluster discovery (kubectl)
  - Terraform state files
  - Docker Compose files
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import networkx as nx
import structlog

log = structlog.get_logger()

# Node types and their base risk multipliers
NODE_TYPE_RISK = {
    "external":  0.9,
    "security":  0.2,
    "infra":     0.3,
    "service":   0.5,
    "data":      0.7,
}

# Edge types
EDGE_TYPES = {"public", "filtered", "internal", "privileged"}


def build_from_dict(definition: dict[str, Any]) -> nx.DiGraph:
    """
    Build a NetworkX DiGraph from a JSON architecture definition.

    Expected format:
    {
      "nodes": [{"id": "apigw", "label": "API Gateway", "type": "service", "risk": 0.6}],
      "edges": [{"source": "lb", "target": "apigw", "type": "internal"}]
    }
    """
    G = nx.DiGraph()

    for node in definition.get("nodes", []):
        base_risk = NODE_TYPE_RISK.get(node.get("type", "service"), 0.5)
        G.add_node(
            node["id"],
            label=node.get("label", node["id"]),
            node_type=node.get("type", "service"),
            risk=node.get("risk", base_risk),
            cves=node.get("cves", []),
            metadata=node.get("metadata", {}),
        )

    for edge in definition.get("edges", []):
        edge_type = edge.get("type", "internal")
        if edge_type not in EDGE_TYPES:
            log.warning("graph.unknown_edge_type", edge_type=edge_type)
        G.add_edge(
            edge["source"],
            edge["target"],
            edge_type=edge_type,
            weight=edge.get("weight", _default_edge_weight(edge_type)),
        )

    log.info("graph.built", nodes=G.number_of_nodes(), edges=G.number_of_edges())
    return G


def build_from_file(path: str | Path) -> nx.DiGraph:
    """Load architecture definition from a JSON file."""
    data = json.loads(Path(path).read_text())
    return build_from_dict(data)


def _default_edge_weight(edge_type: str) -> float:
    return {"public": 1.0, "filtered": 0.6, "internal": 0.4, "privileged": 0.8}.get(edge_type, 0.5)


def compute_risk_scores(G: nx.DiGraph) -> nx.DiGraph:
    """
    Propagate risk scores through the graph using PageRank-like diffusion.
    A node's effective risk = its own risk + weighted sum of upstream risks.
    """
    pr = nx.pagerank(G, alpha=0.85, weight="weight")
    for node_id, pg_score in pr.items():
        base_risk = G.nodes[node_id].get("risk", 0.5)
        G.nodes[node_id]["effective_risk"] = min(1.0, base_risk * 0.7 + pg_score * 0.3)
    return G


def get_attack_surface_nodes(G: nx.DiGraph) -> list[str]:
    """Return nodes reachable from external/internet nodes."""
    external = [n for n, d in G.nodes(data=True) if d.get("node_type") == "external"]
    reachable: set[str] = set()
    for src in external:
        reachable.update(nx.descendants(G, src))
    return list(reachable)
