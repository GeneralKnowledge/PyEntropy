"""Tests for generator state."""

from __future__ import annotations

import pytest

from pyentropy.state import GeneratorState, GeneratorStatus


def test_uninitialized_until_initialize() -> None:
    s = GeneratorState()
    assert s.status is GeneratorStatus.UNINITIALIZED
    assert not s.is_ready
    with pytest.raises(RuntimeError):
        s.generate(16)


def test_initialize_marks_ready() -> None:
    s = GeneratorState()
    s.initialize(b"seed-material-for-testing-!!!!!!!")
    assert s.is_ready
    assert s.status is GeneratorStatus.READY


def test_generate_length_and_counter() -> None:
    s = GeneratorState()
    s.initialize(b"seed-A")
    out = s.generate(40)
    assert len(out) == 40
    c = s.public_counters()
    assert c.bytes_generated == 40
    assert c.generation_count == 1
    assert c.counter > 0


def test_state_changes_after_generate() -> None:
    s = GeneratorState()
    s.initialize(b"seed-B")
    snap1 = s._experimental_snapshot()
    s.generate(32)
    snap2 = s._experimental_snapshot()
    assert snap1["secret"] != snap2["secret"]


def test_successive_output_not_identical() -> None:
    s = GeneratorState()
    s.initialize(b"seed-C")
    a = s.generate(32)
    b = s.generate(32)
    assert a != b


def test_zero_length() -> None:
    s = GeneratorState()
    s.initialize(b"seed-D")
    assert s.generate(0) == b""


def test_negative_length() -> None:
    s = GeneratorState()
    s.initialize(b"seed-E")
    with pytest.raises(ValueError):
        s.generate(-1)


def test_reseed_changes_secret() -> None:
    s = GeneratorState()
    s.initialize(b"seed-F")
    before = s._experimental_snapshot()["secret"]
    s.reseed(b"pool-material", reason="test")
    after = s._experimental_snapshot()["secret"]
    assert before != after
    assert s.public_counters().reseed_count == 1


def test_public_counters_hide_secret() -> None:
    s = GeneratorState()
    s.initialize(b"seed-G")
    c = s.public_counters()
    assert not hasattr(c, "secret")
    d = c.__dict__
    assert "secret" not in d


def test_experimental_restore() -> None:
    s = GeneratorState()
    s.initialize(b"seed-H")
    s.generate(16)
    snap = s._experimental_snapshot()
    later = s.generate(16)
    s._experimental_restore(snap)
    again = s.generate(16)
    assert again == later
