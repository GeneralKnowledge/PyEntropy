"""Property-style tests without third-party property frameworks."""

from __future__ import annotations

import pytest

from pyentropy import RNG, TestRNG, ValidationError

REQUEST_SIZES = [0, 1, 2, 3, 7, 8, 9, 16, 31, 32, 33, 64, 1024, 65536]
RANDBELOW_NS = [1, 2, 3, 10, 255, 256, 257, 1000, 2**16 + 3, 10**9 + 7]


@pytest.fixture(scope="module")
def rng() -> RNG:
    return RNG()


@pytest.mark.parametrize("n", REQUEST_SIZES)
def test_bytes_length_property(rng: RNG, n: int) -> None:
    out = rng.bytes(n)
    assert len(out) == n
    assert isinstance(out, bytes)


@pytest.mark.parametrize("n", REQUEST_SIZES)
def test_testrng_bytes_length(n: int) -> None:
    out = TestRNG(b"prop").bytes(n)
    assert len(out) == n


@pytest.mark.parametrize("n", RANDBELOW_NS)
def test_randbelow_in_range(rng: RNG, n: int) -> None:
    for _ in range(30):
        r = rng.randbelow(n)
        assert 0 <= r < n


def test_testrng_sequence_stable_across_sizes() -> None:
    """Consuming the same total byte count in chunks matches one shot."""
    a = TestRNG(b"chunk-eq")
    b = TestRNG(b"chunk-eq")
    one = a.bytes(100)
    parts = b.bytes(40) + b.bytes(35) + b.bytes(25)
    assert one == parts


def test_integer_bounds_property(rng: RNG) -> None:
    for lo, hi in [(-10, 10), (0, 0), (5, 5), (-1000, -990), (2**30, 2**30 + 50)]:
        for _ in range(20):
            v = rng.integer(lo, hi)
            assert lo <= v <= hi


def test_validation_rejects_bool() -> None:
    rng = TestRNG(b"x")
    with pytest.raises(ValidationError):
        rng.bytes(True)  # type: ignore[arg-type]


def test_hex_length_property(rng: RNG) -> None:
    for n in (0, 1, 8, 32):
        assert len(rng.hex(n)) == n * 2
