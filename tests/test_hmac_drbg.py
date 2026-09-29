"""Tests for HMAC-DRBG (stdlib hmac/hashlib primitive only)."""

from __future__ import annotations

import pytest

from pyentropy.hmac_drbg import HmacDrbg


def test_instantiate_requires_entropy() -> None:
    d = HmacDrbg()
    with pytest.raises(ValueError):
        d.instantiate(b"")


def test_generate_before_instantiate_fails() -> None:
    d = HmacDrbg()
    with pytest.raises(RuntimeError):
        d.generate(16)


def test_deterministic_same_seed() -> None:
    a = HmacDrbg()
    b = HmacDrbg()
    a.instantiate(b"entropy-input-AAAA", nonce=b"n1", personalization_string=b"p")
    b.instantiate(b"entropy-input-AAAA", nonce=b"n1", personalization_string=b"p")
    assert a.generate(64) == b.generate(64)


def test_different_entropy_different_output() -> None:
    a = HmacDrbg()
    b = HmacDrbg()
    a.instantiate(b"entropy-A")
    b.instantiate(b"entropy-B")
    assert a.generate(32) != b.generate(32)


def test_generate_length_and_zero() -> None:
    d = HmacDrbg()
    d.instantiate(b"seed-material")
    assert d.generate(0) == b""
    assert len(d.generate(1)) == 1
    assert len(d.generate(100)) == 100


def test_state_changes_after_generate() -> None:
    d = HmacDrbg()
    d.instantiate(b"seed")
    s1 = d._experimental_snapshot()
    d.generate(32)
    s2 = d._experimental_snapshot()
    assert s1["key"] != s2["key"] or s1["v"] != s2["v"]
    assert s2["reseed_counter"] == s1["reseed_counter"] + 1  # type: ignore[operator]


def test_reseed_changes_stream() -> None:
    d = HmacDrbg()
    d.instantiate(b"seed")
    d.generate(16)
    snap = d._experimental_snapshot()
    out_a = d.generate(32)
    d._experimental_restore(snap)
    d.reseed(b"fresh-entropy-material!!")
    out_b = d.generate(32)
    assert out_a != out_b


def test_nist_chunking_differs_across_generate_calls() -> None:
    """HMAC-DRBG_Generate Updates once per call — chunking changes the stream."""
    a = HmacDrbg()
    b = HmacDrbg()
    a.instantiate(b"chunk-seed")
    b.instantiate(b"chunk-seed")
    one = a.generate(100)
    parts = b.generate(40) + b.generate(60)
    assert one != parts


def test_update_empty_still_changes_state() -> None:
    d = HmacDrbg()
    d.instantiate(b"seed")
    before = d._experimental_snapshot()
    d.update(b"")
    after = d._experimental_snapshot()
    assert before["key"] != after["key"] or before["v"] != after["v"]


def test_restore_reproduces_output() -> None:
    d = HmacDrbg()
    d.instantiate(b"seed")
    d.generate(8)
    snap = d._experimental_snapshot()
    expected = d.generate(32)
    d._experimental_restore(snap)
    assert d.generate(32) == expected
