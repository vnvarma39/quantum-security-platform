"""
Tests for the quantum-inspired annealing patch optimizer.
"""

import pytest
from backend.quantum.annealing import PatchCandidate, quantum_anneal, AnnealingResult


def make_patch(id, node, label, risk, behavior, delta):
    return PatchCandidate(
        id=id, node_id=node, label=label,
        risk_score=risk, behavior_score=behavior,
        delta_lines=delta, code=f"// patch {id}"
    )


@pytest.fixture
def candidates():
    return [
        [
            make_patch("P1a", "parser", "Bounds Check",   0.06, 0.99, 2),
            make_patch("P1b", "parser", "Dynamic Alloc",  0.21, 0.94, 5),
        ],
        [
            make_patch("P2a", "worker", "Drop Privs",     0.08, 0.98, 3),
            make_patch("P2b", "worker", "Namespace Jail", 0.12, 0.96, 8),
        ],
        [
            make_patch("P3a", "paydb", "Parameterized",   0.04, 0.99, 2),
        ],
    ]


def test_returns_result(candidates):
    result = quantum_anneal(candidates, n_steps=200)
    assert isinstance(result, AnnealingResult)


def test_optimal_patches_count(candidates):
    result = quantum_anneal(candidates, n_steps=200)
    assert len(result.optimal_patches) == len(candidates)


def test_energy_decreases_overall(candidates):
    result = quantum_anneal(candidates, n_steps=500)
    # Final energy should be less than initial
    assert result.final_energy <= result.energy_history[0] + 0.1


def test_energy_history_length(candidates):
    result = quantum_anneal(candidates, n_steps=300)
    assert len(result.energy_history) == 301   # step 0 + 300 steps


def test_tunneling_events_non_negative(candidates):
    result = quantum_anneal(candidates, n_steps=200, tunneling_strength=0.3)
    assert result.tunneling_events >= 0


def test_prefers_low_risk_patch(candidates):
    """Given enough steps, annealing should prefer lower-risk patches."""
    result = quantum_anneal(
        candidates, n_steps=2000,
        weights={"risk": 0.9, "behavior": 0.05, "delta": 0.05}
    )
    parser_patch = next(p for p in result.optimal_patches if p.node_id == "parser")
    # P1a has lower risk (0.06) vs P1b (0.21)
    assert parser_patch.id == "P1a"


def test_empty_candidates_raises():
    with pytest.raises(ValueError):
        quantum_anneal([])


def test_progress_callback_called(candidates):
    calls = []
    quantum_anneal(candidates, n_steps=200, progress_cb=lambda s, t, e: calls.append(s))
    assert len(calls) > 0
