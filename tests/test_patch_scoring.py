"""
Tests for multi-objective patch scoring utilities.
"""

import pytest
from backend.quantum.annealing import PatchCandidate, _energy


def make_patch(risk, behavior, delta):
    return PatchCandidate(
        id="test", node_id="n", label="Test",
        risk_score=risk, behavior_score=behavior,
        delta_lines=delta, code=""
    )


DEFAULT_WEIGHTS = {"risk": 0.5, "behavior": 0.3, "delta": 0.2}


def test_perfect_patch_low_energy():
    patches = [make_patch(risk=0.0, behavior=1.0, delta=1)]
    e = _energy(patches, DEFAULT_WEIGHTS)
    assert e < 0.1


def test_terrible_patch_high_energy():
    patches = [make_patch(risk=1.0, behavior=0.0, delta=100)]
    e = _energy(patches, DEFAULT_WEIGHTS)
    assert e > 0.7


def test_energy_monotone_in_risk():
    """Higher risk should produce higher energy all else equal."""
    e_low  = _energy([make_patch(risk=0.1, behavior=0.99, delta=2)], DEFAULT_WEIGHTS)
    e_high = _energy([make_patch(risk=0.9, behavior=0.99, delta=2)], DEFAULT_WEIGHTS)
    assert e_low < e_high


def test_energy_monotone_in_behavior():
    """Lower behavior preservation should increase energy."""
    e_good = _energy([make_patch(risk=0.1, behavior=0.99, delta=2)], DEFAULT_WEIGHTS)
    e_bad  = _energy([make_patch(risk=0.1, behavior=0.50, delta=2)], DEFAULT_WEIGHTS)
    assert e_good < e_bad


def test_energy_monotone_in_delta():
    """More code churn should increase energy."""
    e_small = _energy([make_patch(risk=0.1, behavior=0.99, delta=2)],  DEFAULT_WEIGHTS)
    e_large = _energy([make_patch(risk=0.1, behavior=0.99, delta=50)], DEFAULT_WEIGHTS)
    assert e_small < e_large


def test_multiple_patches_averaged():
    """Energy of multiple patches should be averaged, not summed."""
    p = make_patch(risk=0.2, behavior=0.9, delta=3)
    e_one  = _energy([p],    DEFAULT_WEIGHTS)
    e_two  = _energy([p, p], DEFAULT_WEIGHTS)
    assert abs(e_one - e_two) < 1e-9


def test_empty_patches_returns_inf():
    e = _energy([], DEFAULT_WEIGHTS)
    assert e == float("inf")


def test_weight_sensitivity():
    """Changing weights should shift the energy accordingly."""
    patch = make_patch(risk=0.8, behavior=0.5, delta=5)
    e_risk_heavy = _energy([patch], {"risk": 0.9, "behavior": 0.05, "delta": 0.05})
    e_behav_heavy = _energy([patch], {"risk": 0.05, "behavior": 0.9, "delta": 0.05})
    # patch has high risk → risk-heavy weighting should produce higher energy
    assert e_risk_heavy > e_behav_heavy
