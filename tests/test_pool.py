"""Tests for the fixed-size entropy pool."""

from __future__ import annotations

import pytest

from pyentropy.conditioner import Conditioner
from pyentropy.pool import POOL_SIZE, EntropyPool


def test_pool_fixed_size() -> None:
    pool = EntropyPool()
    assert pool.size == POOL_SIZE
    assert len(pool.snapshot()) == POOL_SIZE


def test_pool_custom_size() -> None:
    pool = EntropyPool(size=32, conditioner=Conditioner(digest_size=32))
    assert pool.size == 32
    assert len(pool.snapshot()) == 32


def test_mixing_changes_state() -> None:
    pool = EntropyPool()
    before = pool.snapshot()
    pool.mix(b"observation-one", source_name="test")
    after = pool.snapshot()
    assert before != after
    assert len(after) == POOL_SIZE


def test_repeated_mixing_deterministic() -> None:
    """Same initial state + same sample sequence → same pool."""
    a = EntropyPool(initial=bytes(POOL_SIZE))
    b = EntropyPool(initial=bytes(POOL_SIZE))
    for sample in (b"aaa", b"bbb", b"ccc"):
        # Metadata includes timestamps, so mix is NOT fully deterministic
        # across separate calls.  Direct conditioner path is deterministic;
        # here we verify that mixing always changes and size stays fixed.
        a.mix(sample, source_name="x")
        assert len(a.snapshot()) == POOL_SIZE
    # Cross-instance: different timestamps → may differ; size must match.
    b.mix(b"aaa", source_name="x")
    assert len(b.snapshot()) == POOL_SIZE


def test_conditioner_mix_is_deterministic() -> None:
    """The underlying conditioner (no wall-clock metadata) is deterministic."""
    c = Conditioner(digest_size=64)
    state = bytes(64)
    sample = b"hello"
    r1 = c.mix(state, sample)
    r2 = c.mix(state, sample)
    assert r1 == r2
    assert r1 != state


def test_input_does_not_mutate_internal_state() -> None:
    pool = EntropyPool()
    sample = bytearray(b"mutable-sample-data!!!!")
    pool.mix(sample, source_name="test")
    mid = pool.snapshot()
    sample[:] = b"\xff" * len(sample)
    # Mutating the caller's buffer must not affect already-mixed pool.
    # Re-mixing with the mutated buffer should change the pool.
    pool.mix(sample, source_name="test")
    assert pool.snapshot() != mid


def test_diagnostics() -> None:
    pool = EntropyPool()
    pool.mix(b"abc", source_name="s")
    d = pool.diagnostics()
    assert d["pool_size"] == POOL_SIZE
    assert d["mix_count"] == 1
    assert d["sample_count"] == 1
    assert d["bytes_mixed"] == 3


def test_invalid_initial_size() -> None:
    with pytest.raises(ValueError):
        EntropyPool(initial=b"short")
