"""
Tests for the quantum walk module.
"""

import pytest
import networkx as nx
from backend.quantum.walk import QuantumWalker, WalkResult


@pytest.fixture
def sample_graph():
    G = nx.DiGraph()
    nodes = [
        ("internet", {"risk": 0.9, "node_type": "external"}),
        ("waf",      {"risk": 0.3, "node_type": "security"}),
        ("apigw",    {"risk": 0.6, "node_type": "service"}),
        ("auth",     {"risk": 0.75,"node_type": "service"}),
        ("userdb",   {"risk": 0.7, "node_type": "data"}),
    ]
    G.add_nodes_from(nodes)
    G.add_edges_from([
        ("internet", "waf",   {"edge_type": "public",   "weight": 1.0}),
        ("waf",      "apigw", {"edge_type": "filtered", "weight": 0.6}),
        ("apigw",    "auth",  {"edge_type": "internal", "weight": 0.4}),
        ("auth",     "userdb",{"edge_type": "internal", "weight": 0.4}),
    ])
    return G


def test_walk_returns_result(sample_graph):
    walker = QuantumWalker(sample_graph, n_steps=3, shots=512)
    result = walker.run()
    assert isinstance(result, WalkResult)


def test_probabilities_sum_to_one(sample_graph):
    walker = QuantumWalker(sample_graph, n_steps=3, shots=512)
    result = walker.run()
    total = sum(result.node_probabilities.values())
    assert abs(total - 1.0) < 1e-6, f"Probabilities sum to {total}, expected 1.0"


def test_all_nodes_in_result(sample_graph):
    walker = QuantumWalker(sample_graph, n_steps=3, shots=512)
    result = walker.run()
    for node in sample_graph.nodes:
        assert node in result.node_probabilities


def test_entropy_is_positive(sample_graph):
    walker = QuantumWalker(sample_graph, n_steps=3, shots=512)
    result = walker.run()
    assert result.entanglement_entropy >= 0


def test_high_risk_nodes_sorted(sample_graph):
    walker = QuantumWalker(sample_graph, n_steps=3, shots=512)
    result = walker.run()
    probs = [result.node_probabilities[n] for n in result.high_risk_nodes]
    assert probs == sorted(probs, reverse=True)


def test_steps_recorded(sample_graph):
    walker = QuantumWalker(sample_graph, n_steps=5, shots=256)
    result = walker.run()
    assert result.steps_taken == 5
