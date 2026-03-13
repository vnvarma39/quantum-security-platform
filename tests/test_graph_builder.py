"""
Tests for the architecture graph builder.
"""

import pytest
import networkx as nx
from backend.graph.builder import (
    build_from_dict,
    compute_risk_scores,
    get_attack_surface_nodes,
)

SAMPLE_DEF = {
    "nodes": [
        {"id": "internet",  "label": "Internet",     "type": "external",  "risk": 0.9},
        {"id": "waf",       "label": "WAF",           "type": "security",  "risk": 0.3},
        {"id": "lb",        "label": "Load Balancer", "type": "infra",     "risk": 0.2},
        {"id": "apigw",     "label": "API Gateway",   "type": "service",   "risk": 0.6},
        {"id": "auth",      "label": "Auth Service",  "type": "service",   "risk": 0.75},
        {"id": "userdb",    "label": "User DB",       "type": "data",      "risk": 0.7},
        {"id": "paydb",     "label": "Payment DB",    "type": "data",      "risk": 0.9},
    ],
    "edges": [
        {"source": "internet", "target": "waf",    "type": "public"},
        {"source": "waf",      "target": "lb",     "type": "filtered"},
        {"source": "lb",       "target": "apigw",  "type": "internal"},
        {"source": "apigw",    "target": "auth",   "type": "internal"},
        {"source": "auth",     "target": "userdb", "type": "internal"},
        {"source": "auth",     "target": "paydb",  "type": "privileged"},
    ],
}


@pytest.fixture
def graph():
    return build_from_dict(SAMPLE_DEF)


def test_node_count(graph):
    assert graph.number_of_nodes() == 7


def test_edge_count(graph):
    assert graph.number_of_edges() == 6


def test_node_attributes(graph):
    assert graph.nodes["apigw"]["node_type"] == "service"
    assert graph.nodes["apigw"]["risk"] == 0.6
    assert graph.nodes["apigw"]["label"] == "API Gateway"


def test_edge_types(graph):
    assert graph["internet"]["waf"]["edge_type"] == "public"
    assert graph["auth"]["paydb"]["edge_type"] == "privileged"


def test_graph_is_directed(graph):
    assert isinstance(graph, nx.DiGraph)


def test_compute_risk_scores(graph):
    scored = compute_risk_scores(graph)
    for node in scored.nodes:
        eff = scored.nodes[node].get("effective_risk")
        assert eff is not None, f"effective_risk missing for {node}"
        assert 0.0 <= eff <= 1.0, f"effective_risk out of range for {node}: {eff}"


def test_attack_surface_includes_reachable(graph):
    surface = get_attack_surface_nodes(graph)
    # waf, lb, apigw, auth, userdb, paydb should all be reachable from internet
    for expected in ["waf", "lb", "apigw", "auth", "userdb", "paydb"]:
        assert expected in surface


def test_attack_surface_excludes_external(graph):
    surface = get_attack_surface_nodes(graph)
    assert "internet" not in surface


def test_missing_edge_type_defaults(graph):
    defn = {
        "nodes": [{"id": "a"}, {"id": "b"}],
        "edges": [{"source": "a", "target": "b"}],  # no type
    }
    G = build_from_dict(defn)
    assert G["a"]["b"]["edge_type"] == "internal"
