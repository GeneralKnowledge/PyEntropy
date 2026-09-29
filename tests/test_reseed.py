"""Tests for reseeding behaviour."""

from __future__ import annotations

import time

from pyentropy.entropy.adversarial import ConstantEntropy
from pyentropy.entropy.composite import EntropyCollector
from pyentropy.pool import EntropyPool
from pyentropy.reseed import ReseedController, ReseedPolicy
from pyentropy.rng import RNG, TestRNG
from pyentropy.state import GeneratorState


def test_reseed_increments_count() -> None:
    rng = RNG()
    n0 = rng.status()["reseed_count"]
    rng.reseed()
    rng.reseed()
    assert rng.status()["reseed_count"] == n0 + 2


def test_reseed_changes_output_stream() -> None:
    """After capturing state, reseed should prevent reproduction of later output."""
    rng = TestRNG(b"reseed-stream")
    rng.bytes(16)  # warm
    snap = rng._experimental_state_snapshot()
    after_a = rng.bytes(32)
    rng._experimental_restore_state(snap)
    rng.reseed(b"different-pool-material")
    after_b = rng.bytes(32)
    assert after_a != after_b


def test_byte_threshold_triggers_reseed() -> None:
    pool = EntropyPool()
    collector = EntropyCollector(
        sources=[ConstantEntropy(b"\xaa" * 32)],
        pool=pool,
    )
    state = GeneratorState()
    collector.collect_once()
    state.initialize(pool.snapshot())
    ctrl = ReseedController(
        collector,
        state,
        policy=ReseedPolicy(byte_threshold=64, time_threshold=10_000.0),
    )
    before = state.public_counters().reseed_count
    ctrl.note_generated(64)
    assert ctrl.maybe_reseed() is True
    assert state.public_counters().reseed_count == before + 1


def test_time_threshold_triggers_reseed() -> None:
    pool = EntropyPool()
    collector = EntropyCollector(
        sources=[ConstantEntropy(b"\xbb" * 32)],
        pool=pool,
    )
    state = GeneratorState()
    collector.collect_once()
    state.initialize(pool.snapshot())
    ctrl = ReseedController(
        collector,
        state,
        policy=ReseedPolicy(byte_threshold=10**12, time_threshold=0.01),
    )
    time.sleep(0.02)
    before = state.public_counters().reseed_count
    assert ctrl.maybe_reseed() is True
    assert state.public_counters().reseed_count == before + 1


def test_reseed_mixes_with_existing_secret() -> None:
    """Reseed must not simply replace Key with pool bytes."""
    s = GeneratorState()
    s.initialize(b"original-secret-seed-material")
    original = s._experimental_snapshot()["key"]
    pool_bytes = b"\x00" * 64
    s.reseed(pool_bytes, reason="test")
    new = s._experimental_snapshot()["key"]
    assert new != original
    assert new != pool_bytes[:32]
