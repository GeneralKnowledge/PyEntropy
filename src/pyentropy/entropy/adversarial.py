"""Adversarial / fake entropy sources for experiments.

Educational RNG — not a production CSPRNG.

These sources intentionally produce predictable or failing observations
so that collectors, pools, and generators can be stress-tested.
"""

from __future__ import annotations

import struct
import time

from pyentropy.entropy.base import EntropySource
from pyentropy.exceptions import EntropySourceError


class ConstantEntropy(EntropySource):
    """Always returns the same byte string."""

    name = "constant"

    def __init__(self, value: bytes = b"\x00" * 64) -> None:
        self._value = bytes(value)

    def collect(self) -> bytes:
        return self._value


class CounterEntropy(EntropySource):
    """Returns an incrementing counter packed as bytes."""

    name = "counter"

    def __init__(self) -> None:
        self._n = 0

    def collect(self) -> bytes:
        self._n += 1
        return struct.pack(">Q", self._n) * 8


class TimestampEntropy(EntropySource):
    """Returns only the current wall-clock / monotonic timestamps.

    Predictable to an observer who knows approximate collection time.
    """

    name = "timestamp"

    def collect(self) -> bytes:
        return struct.pack(">QQ", time.time_ns(), time.monotonic_ns())


class RepeatingEntropy(EntropySource):
    """Cycles through a short fixed pattern."""

    name = "repeating"

    def __init__(self, pattern: bytes = b"ABCD") -> None:
        if not pattern:
            raise ValueError("pattern must be non-empty")
        self._pattern = bytes(pattern)
        self._i = 0

    def collect(self) -> bytes:
        self._i = (self._i + 1) % len(self._pattern)
        rotated = self._pattern[self._i :] + self._pattern[: self._i]
        return (rotated * (64 // len(rotated) + 1))[:64]


class FailingEntropy(EntropySource):
    """Always raises — models an unavailable source."""

    name = "failing"

    def __init__(self, message: str = "source unavailable") -> None:
        self._message = message

    def collect(self) -> bytes:
        raise EntropySourceError(self._message)


class EmptyEntropy(EntropySource):
    """Returns empty bytes — treated as a collection failure."""

    name = "empty"

    def collect(self) -> bytes:
        return b""
