"""Tests for RNG and TestRNG."""

from __future__ import annotations

import threading

import pytest

from pyentropy import RNG, TestRNG, ValidationError
from pyentropy.entropy.adversarial import ConstantEntropy, FailingEntropy
from pyentropy.exceptions import InitializationError


def test_bytes_length() -> None:
    rng = RNG()
    assert len(rng.bytes(32)) == 32
    assert rng.bytes(0) == b""


def test_negative_bytes() -> None:
    rng = RNG()
    with pytest.raises(ValidationError):
        rng.bytes(-1)


def test_successive_not_identical() -> None:
    rng = RNG()
    assert rng.bytes(32) != rng.bytes(32)


def test_large_request() -> None:
    rng = RNG()
    data = rng.bytes(65536)
    assert len(data) == 65536


def test_hex() -> None:
    rng = RNG()
    h = rng.hex(16)
    assert len(h) == 32
    int(h, 16)  # valid hex


def test_randbits() -> None:
    rng = RNG()
    assert rng.randbits(0) == 0
    with pytest.raises(ValidationError):
        rng.randbits(-1)
    v = rng.randbits(8)
    assert 0 <= v < 256
    v256 = rng.randbits(256)
    assert 0 <= v256 < (1 << 256)


def test_randbelow_range() -> None:
    rng = RNG()
    for n in (1, 2, 3, 10, 255, 256, 257, 1000, 10**6):
        for _ in range(50):
            r = rng.randbelow(n)
            assert 0 <= r < n


def test_randbelow_n1() -> None:
    rng = RNG()
    assert all(rng.randbelow(1) == 0 for _ in range(20))


def test_randbelow_invalid() -> None:
    rng = RNG()
    with pytest.raises(ValidationError):
        rng.randbelow(0)
    with pytest.raises(ValidationError):
        rng.randbelow(-5)


def test_integer_inclusive() -> None:
    rng = RNG()
    for _ in range(100):
        v = rng.integer(-50, 50)
        assert -50 <= v <= 50


def test_integer_invalid_range() -> None:
    rng = RNG()
    with pytest.raises(ValidationError):
        rng.integer(10, 5)


def test_status_no_secret() -> None:
    rng = RNG()
    st = rng.status()
    assert st["state"] == "READY"
    assert "secret" not in st
    assert "pool_bytes" not in st
    blob = str(st)
    assert "secret" not in blob.lower() or "secret" not in st


def test_reseed() -> None:
    rng = RNG()
    before = rng.status()["reseed_count"]
    a = rng.bytes(32)
    rng.reseed()
    b = rng.bytes(32)
    assert a != b
    assert rng.status()["reseed_count"] == before + 1


def test_init_fails_with_all_failing_sources() -> None:
    with pytest.raises(InitializationError):
        RNG(sources=[FailingEntropy(), FailingEntropy(message="also down")])


def test_testrng_deterministic() -> None:
    a = TestRNG(b"fixed-seed")
    b = TestRNG(b"fixed-seed")
    assert a.bytes(64) == b.bytes(64)
    assert TestRNG(b"fixed-seed").randbits(128) == TestRNG(b"fixed-seed").randbits(128)


def test_testrng_different_seeds() -> None:
    a = TestRNG(b"seed-A").bytes(32)
    b = TestRNG(b"seed-B").bytes(32)
    assert a != b


def test_testrng_int_seed() -> None:
    assert TestRNG(42).bytes(16) == TestRNG(42).bytes(16)


def test_thread_safety_smoke() -> None:
    rng = RNG()
    errors: list[BaseException] = []
    results: list[bytes] = []

    def worker() -> None:
        try:
            for _ in range(20):
                results.append(rng.bytes(16))
        except BaseException as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors
    assert len(results) == 8 * 20
    # Extremely unlikely all identical if generator works.
    assert len(set(results)) > 1


def test_constant_sources_still_start() -> None:
    """Predictable sources still allow startup — but output depends on them.

    The system must not silently refuse; experiments study the consequence.
    """
    rng = RNG(sources=[ConstantEntropy(b"\x01" * 64), ConstantEntropy(b"\x02" * 64)])
    assert len(rng.bytes(32)) == 32
