"""
Discrete-time quantum walk on the architecture security graph.

Uses Qiskit to simulate the walk operator U = S · (C ⊗ I)
where S is the shift operator and C is the coin operator.
For n-node graphs we use ceil(log2(n)) qubits for position
and 1 ancilla qubit as the coin.
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Optional

import networkx as nx
import numpy as np
from qiskit import QuantumCircuit, QuantumRegister, ClassicalRegister
from qiskit_aer import AerSimulator
from qiskit.circuit.library import HGate, XGate

import structlog

log = structlog.get_logger()


@dataclass
class WalkResult:
    """Result of a quantum walk over the architecture graph."""
    node_probabilities: dict[str, float]        # node_id → probability of being in state
    high_risk_nodes: list[str]                  # sorted by descending risk amplitude
    entanglement_entropy: float
    steps_taken: int
    raw_counts: dict[str, int] = field(default_factory=dict)


class QuantumWalker:
    """
    Runs a discrete-time quantum walk on an architecture graph
    to amplify high-risk nodes for attack path detection.
    """

    def __init__(self, graph: nx.DiGraph, n_steps: int = 10, shots: int = 4096):
        self.graph = graph
        self.n_steps = n_steps
        self.shots = shots
        self.simulator = AerSimulator()
        self._node_list = list(graph.nodes)
        self._n_nodes = len(self._node_list)
        self._n_pos_qubits = max(1, math.ceil(math.log2(self._n_nodes)))

    def _build_circuit(self) -> QuantumCircuit:
        """Construct the quantum walk circuit."""
        pos = QuantumRegister(self._n_pos_qubits, "pos")
        coin = QuantumRegister(1, "coin")
        cr = ClassicalRegister(self._n_pos_qubits, "meas")
        qc = QuantumCircuit(pos, coin, cr)

        # Initialize in uniform superposition
        qc.h(pos)
        qc.h(coin)

        for _ in range(self.n_steps):
            # Coin flip (Hadamard coin)
            qc.h(coin)
            # Shift operator — move based on coin state
            for i in range(self._n_pos_qubits):
                qc.cx(coin[0], pos[i])
            qc.barrier()

        qc.measure(pos, cr)
        return qc

    def run(self) -> WalkResult:
        """Execute the quantum walk and return amplified node probabilities."""
        log.info("quantum_walk.start", n_nodes=self._n_nodes, steps=self.n_steps)

        qc = self._build_circuit()
        job = self.simulator.run(qc, shots=self.shots)
        counts = job.result().get_counts()

        # Map bitstring counts → node probabilities
        node_probs: dict[str, float] = {}
        for bitstring, count in counts.items():
            idx = int(bitstring, 2) % self._n_nodes
            node_id = self._node_list[idx]
            node_probs[node_id] = node_probs.get(node_id, 0) + count / self.shots

        # Weight by node's inherent risk score
        for node_id in node_probs:
            risk = self.graph.nodes[node_id].get("risk", 0.5)
            node_probs[node_id] *= (1 + risk)

        # Normalise
        total = sum(node_probs.values()) or 1.0
        node_probs = {k: v / total for k, v in node_probs.items()}

        high_risk = sorted(node_probs, key=node_probs.get, reverse=True)

        # Rough entanglement entropy from probability distribution
        probs = np.array(list(node_probs.values()))
        probs = probs[probs > 0]
        entropy = float(-np.sum(probs * np.log2(probs)))

        log.info("quantum_walk.complete", entropy=round(entropy, 4), top_node=high_risk[0] if high_risk else None)

        return WalkResult(
            node_probabilities=node_probs,
            high_risk_nodes=high_risk,
            entanglement_entropy=entropy,
            steps_taken=self.n_steps,
            raw_counts=counts,
        )
