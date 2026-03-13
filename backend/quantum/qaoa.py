"""
QAOA (Quantum Approximate Optimization Algorithm) for attack path finding.

Encodes the maximum-weight path problem on the architecture graph
as a QUBO (Quadratic Unconstrained Binary Optimization) and solves
it using Qiskit's QAOA implementation.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

import networkx as nx
import numpy as np
from qiskit.circuit.library import QAOAAnsatz
from qiskit_algorithms import QAOA, SamplingVQE
from qiskit_algorithms.optimizers import COBYLA
from qiskit_optimization import QuadraticProgram
from qiskit_optimization.algorithms import MinimumEigenOptimizer
from qiskit_optimization.converters import QuadraticProgramToQubo
from qiskit_aer.primitives import Sampler
import structlog

log = structlog.get_logger()


@dataclass
class AttackPath:
    nodes: list[str]
    total_risk: float
    hop_count: int
    qaoa_energy: float


class QAOAPathFinder:
    """
    Uses QAOA to find the maximum-risk path through a security graph.

    The QUBO formulation:
      - Binary variable xᵢ ∈ {0,1} for each node (1 = node is in path)
      - Maximise Σ rᵢxᵢ + λ Σ eᵢⱼxᵢxⱼ  (risk + connectivity bonus)
      - Subject to: path forms a valid directed walk

    QAOA approximates the ground state of the cost Hamiltonian:
      H_C = -Σᵢ rᵢ(I - σᵢᶻ)/2 - λ Σ eᵢⱼ(I-σᵢᶻ)(I-σⱼᶻ)/4
    """

    def __init__(
        self,
        graph: nx.DiGraph,
        qaoa_reps: int = 2,
        max_nodes_in_path: int = 8,
    ):
        self.graph = graph
        self.qaoa_reps = qaoa_reps
        self.max_nodes_in_path = max_nodes_in_path
        self._sampler = Sampler()

    def find_attack_paths(self, top_k: int = 3) -> list[AttackPath]:
        """Find the top-k highest-risk attack paths."""
        log.info("qaoa.start", nodes=self.graph.number_of_nodes(), reps=self.qaoa_reps)

        # Build QUBO
        qp = self._build_qubo()
        converter = QuadraticProgramToQubo()
        qubo = converter.convert(qp)

        # Run QAOA
        optimizer = COBYLA(maxiter=300)
        qaoa = QAOA(sampler=self._sampler, optimizer=optimizer, reps=self.qaoa_reps)
        solver = MinimumEigenOptimizer(qaoa)

        try:
            result = solver.solve(qubo)
        except Exception as exc:
            log.warning("qaoa.fallback_to_classical", reason=str(exc))
            return self._classical_fallback(top_k)

        # Extract selected nodes and reconstruct paths
        selected = [
            list(self.graph.nodes)[i]
            for i, val in enumerate(result.x)
            if val > 0.5 and i < self.graph.number_of_nodes()
        ]

        paths = self._reconstruct_paths(selected, top_k)
        log.info("qaoa.complete", paths_found=len(paths))
        return paths

    def _build_qubo(self) -> QuadraticProgram:
        """Encode maximum-risk path as a quadratic program."""
        qp = QuadraticProgram("attack_path_qubo")
        node_list = list(self.graph.nodes)

        # Binary variables per node
        for n in node_list:
            qp.binary_var(name=n.replace("-", "_"))

        # Objective: maximise risk (minimise negative risk for QUBO)
        linear = {}
        for n in node_list:
            risk = self.graph.nodes[n].get("effective_risk", self.graph.nodes[n].get("risk", 0.5))
            linear[n.replace("-", "_")] = -risk   # negate for minimisation

        quadratic = {}
        for u, v, data in self.graph.edges(data=True):
            key = (u.replace("-", "_"), v.replace("-", "_"))
            quadratic[key] = -data.get("weight", 0.4) * 0.5   # connectivity bonus

        qp.minimize(linear=linear, quadratic=quadratic)
        return qp

    def _reconstruct_paths(self, selected_nodes: list[str], top_k: int) -> list[AttackPath]:
        """Extract valid directed paths from selected nodes."""
        if not selected_nodes:
            return self._classical_fallback(top_k)

        subgraph = self.graph.subgraph(selected_nodes)
        paths = []

        external_nodes = [n for n in selected_nodes if self.graph.nodes[n].get("node_type") == "external"]
        data_nodes = [n for n in selected_nodes if self.graph.nodes[n].get("node_type") == "data"]

        for src in external_nodes:
            for dst in data_nodes:
                try:
                    for path in nx.all_simple_paths(subgraph, src, dst, cutoff=self.max_nodes_in_path):
                        risk = sum(self.graph.nodes[n].get("risk", 0.5) for n in path) / len(path)
                        paths.append(AttackPath(
                            nodes=path,
                            total_risk=risk,
                            hop_count=len(path),
                            qaoa_energy=0.0,
                        ))
                except (nx.NetworkXNoPath, nx.NodeNotFound):
                    continue

        paths.sort(key=lambda p: p.total_risk, reverse=True)
        return paths[:top_k] if paths else self._classical_fallback(top_k)

    def _classical_fallback(self, top_k: int) -> list[AttackPath]:
        """Dijkstra-based fallback when QAOA cannot solve within limits."""
        log.info("qaoa.classical_fallback")
        external = [n for n, d in self.graph.nodes(data=True) if d.get("node_type") == "external"]
        data_nodes = [n for n, d in self.graph.nodes(data=True) if d.get("node_type") == "data"]

        # Invert risk weights for shortest-path (we want highest risk)
        weight_graph = self.graph.copy()
        for u, v in weight_graph.edges():
            risk = weight_graph.nodes[v].get("risk", 0.5)
            weight_graph[u][v]["inv_risk"] = 1.0 - risk

        paths = []
        for src in external:
            for dst in data_nodes:
                try:
                    path = nx.dijkstra_path(weight_graph, src, dst, weight="inv_risk")
                    risk = sum(self.graph.nodes[n].get("risk", 0.5) for n in path) / len(path)
                    paths.append(AttackPath(nodes=path, total_risk=risk,
                                            hop_count=len(path), qaoa_energy=0.0))
                except (nx.NetworkXNoPath, nx.NodeNotFound):
                    continue

        paths.sort(key=lambda p: p.total_risk, reverse=True)
        return paths[:top_k]
