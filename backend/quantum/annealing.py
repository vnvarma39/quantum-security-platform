"""
Quantum-Inspired Simulated Annealing for Patch Synthesis.

Models the patch search space as an energy landscape and uses
a quantum-inspired annealing schedule (with tunneling probability)
to find the globally optimal combination of patches that:
  - Minimises security risk
  - Preserves program behaviour
  - Minimises code delta (lines changed)
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass, field
from typing import Callable

import numpy as np
import structlog

log = structlog.get_logger()


@dataclass
class PatchCandidate:
    id: str
    node_id: str
    label: str
    risk_score: float        # 0–1, lower is better
    behavior_score: float    # 0–1, higher is better
    delta_lines: int
    code: str


@dataclass
class AnnealingResult:
    optimal_patches: list[PatchCandidate]
    final_energy: float
    energy_history: list[float]
    temperature_history: list[float]
    n_iterations: int
    tunneling_events: int


def _energy(patches: list[PatchCandidate], weights: dict) -> float:
    """
    Multi-objective cost function.
    E = α·risk + β·(1 - behavior) + γ·(delta / max_delta)
    """
    if not patches:
        return float("inf")
    alpha = weights.get("risk", 0.5)
    beta  = weights.get("behavior", 0.3)
    gamma = weights.get("delta", 0.2)

    max_delta = max(p.delta_lines for p in patches) or 1
    risk_term     = alpha * sum(p.risk_score for p in patches) / len(patches)
    behavior_term = beta  * sum(1 - p.behavior_score for p in patches) / len(patches)
    delta_term    = gamma * sum(p.delta_lines / max_delta for p in patches) / len(patches)
    return risk_term + behavior_term + delta_term


def quantum_anneal(
    candidates: list[list[PatchCandidate]],   # candidates[i] = options for vuln i
    t_start: float = 100.0,
    t_end: float = 0.01,
    n_steps: int = 2000,
    weights: dict | None = None,
    tunneling_strength: float = 0.15,
    progress_cb: Callable[[int, float, float], None] | None = None,
) -> AnnealingResult:
    """
    Quantum-inspired annealing over the patch combination space.

    Args:
        candidates: For each vulnerability, a list of patch options.
        t_start: Initial (high) temperature.
        t_end: Final (low) temperature.
        n_steps: Total annealing steps.
        weights: Objective weights {risk, behavior, delta}.
        tunneling_strength: Probability of quantum tunneling through a barrier.
        progress_cb: Optional callback(step, temperature, energy).
    """
    weights = weights or {"risk": 0.5, "behavior": 0.3, "delta": 0.2}

    if not candidates:
        raise ValueError("No patch candidates provided.")

    # Initial state: first candidate for each vulnerability
    current = [random.choice(group) for group in candidates]
    current_energy = _energy(current, weights)

    best = list(current)
    best_energy = current_energy

    energy_history: list[float] = [current_energy]
    temp_history:   list[float] = [t_start]
    tunneling_events = 0

    cooling = (t_end / t_start) ** (1.0 / n_steps)
    temperature = t_start

    log.info("annealing.start", n_vulns=len(candidates), t_start=t_start, n_steps=n_steps)

    for step in range(n_steps):
        temperature *= cooling

        # Pick a random vulnerability to swap patch for
        vuln_idx = random.randrange(len(candidates))
        group = candidates[vuln_idx]
        if len(group) <= 1:
            continue

        # Propose new state
        new_patch = random.choice([p for p in group if p is not current[vuln_idx]])
        proposed = list(current)
        proposed[vuln_idx] = new_patch
        proposed_energy = _energy(proposed, weights)

        delta_e = proposed_energy - current_energy

        # Acceptance: Metropolis + quantum tunneling
        accepted = False
        if delta_e < 0:
            accepted = True
        else:
            # Classical Metropolis
            metropolis_p = math.exp(-delta_e / max(temperature, 1e-10))
            # Quantum tunneling: extra acceptance probability independent of temperature
            tunnel_p = tunneling_strength * math.exp(-abs(delta_e) / 0.5)
            if random.random() < metropolis_p + tunnel_p:
                accepted = True
                if random.random() < tunnel_p / (metropolis_p + tunnel_p + 1e-10):
                    tunneling_events += 1

        if accepted:
            current = proposed
            current_energy = proposed_energy
            if current_energy < best_energy:
                best = list(current)
                best_energy = current_energy

        energy_history.append(current_energy)
        temp_history.append(temperature)

        if progress_cb and step % 50 == 0:
            progress_cb(step, temperature, current_energy)

    log.info(
        "annealing.complete",
        final_energy=round(best_energy, 6),
        tunneling_events=tunneling_events,
        n_steps=n_steps,
    )

    return AnnealingResult(
        optimal_patches=best,
        final_energy=best_energy,
        energy_history=energy_history,
        temperature_history=temp_history,
        n_iterations=n_steps,
        tunneling_events=tunneling_events,
    )
