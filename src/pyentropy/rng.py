"""PyEntropy RNG — HMAC-DRBG-backed userspace generator.

Educational / experimental.  NOT a replacement for /dev/urandom,
secrets, or a production OS CSPRNG.

Pipeline::

    entropy sources → observations → collector → pool → conditioner
         → HMAC-DRBG (Instantiate / Generate / Reseed) → random bytes
"""

from __future__ import annotations

import os
import threading
from typing import Any

from pyentropy.diagnostics import uptime_seconds
from pyentropy.encoding import to_hex
from pyentropy.entropy.base import EntropySource
from pyentropy.entropy.composite import EntropyCollector
from pyentropy.exceptions import InitializationError, NotReadyError, ValidationError
from pyentropy.pool import POOL_SIZE, EntropyPool
from pyentropy.reseed import ReseedController, ReseedPolicy
from pyentropy.state import PERSONALIZATION_TEST, GeneratorState


def _validate_non_negative(name: str, value: int) -> None:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValidationError(f"{name} must be an int")
    if value < 0:
        raise ValidationError(f"{name} must be non-negative, got {value}")


def _validate_positive(name: str, value: int) -> None:
    if not isinstance(value, int) or isinstance(value, bool):
        raise ValidationError(f"{name} must be an int")
    if value <= 0:
        raise ValidationError(f"{name} must be positive, got {value}")


class RNG:
    """Environmental-observation-seeded HMAC-DRBG byte generator.

    This class is for education and experimentation.  Do not use it to
    generate private keys or as a drop-in replacement for OS CSPRNGs.
    """

    def __init__(
        self,
        *,
        sources: list[EntropySource] | None = None,
        reseed_bytes: int = 1 * 1024 * 1024,
        reseed_seconds: float = 60.0,
        startup_rounds: int = 3,
        fork_aware: bool = True,
    ) -> None:
        self._lock = threading.RLock()
        self._pool = EntropyPool(size=POOL_SIZE)
        self._collector = EntropyCollector(sources=sources, pool=self._pool)
        self._state = GeneratorState()
        self._reseed = ReseedController(
            self._collector,
            self._state,
            policy=ReseedPolicy(
                byte_threshold=reseed_bytes,
                time_threshold=reseed_seconds,
            ),
        )
        self._fork_aware = fork_aware
        self._pid = os.getpid()
        self._startup(startup_rounds=startup_rounds)

    def _startup(self, *, startup_rounds: int) -> None:
        """Create pool, collect observations, derive initial secret, mark READY."""
        successes = 0
        for _ in range(startup_rounds):
            samples = self._collector.collect_once()
            successes += len(samples)

        if successes < 1:
            raise InitializationError(
                "mandatory initialisation failed: no entropy sources produced "
                "observations.  Refusing to start with predictable state."
            )

        # Require that the pool has been mixed at least once.
        if self._pool.diagnostics()["mix_count"] < 1:
            raise InitializationError(
                "entropy pool was not mixed during startup"
            )

        seed_material = self._pool.snapshot()
        self._state.initialize(seed_material)
        # Track startup as an implicit first reseed baseline.
        self._reseed._bytes_since_reseed = 0  # noqa: SLF001 — internal reset

    def _check_fork(self) -> None:
        """If the process forked, reseed so parent/child do not share state."""
        if not self._fork_aware:
            return
        current = os.getpid()
        if current != self._pid:
            self._pid = current
            self._reseed.reseed(reason="fork_detected")

    def _ensure_ready(self) -> None:
        if not self._state.is_ready:
            raise NotReadyError("generator is not READY")

    def bytes(self, n: int) -> bytes:
        """Return *n* random bytes.  ``n == 0`` returns ``b""``."""
        _validate_non_negative("n", n)
        if n == 0:
            return b""
        with self._lock:
            self._check_fork()
            self._ensure_ready()
            self._reseed.maybe_reseed()
            out = self._state.generate(n)
            self._reseed.note_generated(n)
            return out

    def randbits(self, k: int) -> int:
        """Return an integer with *k* random bits (0 <= result < 2**k)."""
        _validate_non_negative("k", k)
        if k == 0:
            return 0
        nbytes = (k + 7) // 8
        data = self.bytes(nbytes)
        value = int.from_bytes(data, "big")
        # Mask to exactly k bits.
        return value & ((1 << k) - 1)

    def randbelow(self, n: int) -> int:
        """Return a uniform integer in ``[0, n)`` via rejection sampling.

        Never uses ``random_value % n`` alone (modulo bias).
        """
        _validate_positive("n", n)
        if n == 1:
            return 0

        # Number of bits needed to represent n-1.
        k = (n - 1).bit_length()
        while True:
            r = self.randbits(k)
            if r < n:
                return r

    def integer(self, minimum: int, maximum: int) -> int:
        """Return a uniform integer in ``[minimum, maximum]`` inclusive."""
        if not isinstance(minimum, int) or isinstance(minimum, bool):
            raise ValidationError("minimum must be an int")
        if not isinstance(maximum, int) or isinstance(maximum, bool):
            raise ValidationError("maximum must be an int")
        if maximum < minimum:
            raise ValidationError(
                f"invalid range: maximum ({maximum}) < minimum ({minimum})"
            )
        span = maximum - minimum + 1
        return minimum + self.randbelow(span)

    def hex(self, n: int) -> str:
        """Return *n* random bytes encoded as lowercase hex."""
        return to_hex(self.bytes(n))

    def reseed(self) -> None:
        """Explicitly collect fresh observations and reseed the generator."""
        with self._lock:
            self._ensure_ready()
            self._reseed.reseed(reason="explicit")

    def status(self) -> dict[str, Any]:
        """Return diagnostics.  Never includes secret generator state."""
        with self._lock:
            counters = self._state.public_counters()
            coll = self._collector.diagnostics()
            sources = coll.get("sources", {})
            return {
                "state": self._state.status.name,
                "pool_size": self._pool.size,
                "reseed_count": counters.reseed_count,
                "bytes_generated": counters.bytes_generated,
                "generation_count": counters.generation_count,
                "entropy_samples": coll.get("total_samples", 0),
                "source_failures": coll.get("total_failures", 0),
                "last_reseed_reason": counters.last_reseed_reason,
                "last_reseed_at": counters.last_reseed_at,
                "uptime_seconds": uptime_seconds(counters.created_at),
                "sources": sources,
                "pid": self._pid,
                # Explicit absence of secrets:
                # "secret" / "pool_bytes" intentionally omitted.
            }

    # Experimental hooks (not part of the stable public API) -------------

    def _experimental_state_snapshot(self) -> dict[str, object]:
        """Educational state-compromise helper.  Not a public API."""
        return self._state._experimental_snapshot()  # noqa: SLF001

    def _experimental_restore_state(self, snapshot: dict[str, object]) -> None:
        """Restore a compromise snapshot.  Not a public API."""
        self._state._experimental_restore(snapshot)  # noqa: SLF001


class TestRNG:
    """Deterministic HMAC-DRBG for tests and experiments only.

    Same seed → same output sequence.  Completely separate from ``RNG``;
    normal ``RNG()`` never falls back to this mode on entropy failure.
    """

    # Avoid pytest collecting this as a test class.
    __test__ = False

    def __init__(self, seed: bytes | int | str) -> None:
        if isinstance(seed, int):
            if seed < 0:
                raise ValidationError("seed int must be non-negative")
            seed_bytes = seed.to_bytes(max(8, (seed.bit_length() + 7) // 8), "big")
        elif isinstance(seed, str):
            seed_bytes = seed.encode("utf-8")
        elif isinstance(seed, (bytes, bytearray)):
            seed_bytes = bytes(seed)
        else:
            raise ValidationError("seed must be bytes, int, or str")

        if not seed_bytes:
            raise ValidationError("seed must be non-empty")

        # Instantiate HMAC-DRBG directly from the seed — no entropy sources.
        self._state = GeneratorState(personalization=PERSONALIZATION_TEST)
        self._state.initialize(seed_bytes)
        self._lock = threading.RLock()
        self._seed_repr = (
            repr(seed) if not isinstance(seed, bytes) else f"bytes[{len(seed)}]"
        )

    def bytes(self, n: int) -> bytes:
        _validate_non_negative("n", n)
        if n == 0:
            return b""
        with self._lock:
            return self._state.generate(n)

    def randbits(self, k: int) -> int:
        _validate_non_negative("k", k)
        if k == 0:
            return 0
        nbytes = (k + 7) // 8
        data = self.bytes(nbytes)
        return int.from_bytes(data, "big") & ((1 << k) - 1)

    def randbelow(self, n: int) -> int:
        _validate_positive("n", n)
        if n == 1:
            return 0
        k = (n - 1).bit_length()
        while True:
            r = self.randbits(k)
            if r < n:
                return r

    def integer(self, minimum: int, maximum: int) -> int:
        if maximum < minimum:
            raise ValidationError(
                f"invalid range: maximum ({maximum}) < minimum ({minimum})"
            )
        return minimum + self.randbelow(maximum - minimum + 1)

    def hex(self, n: int) -> str:
        return to_hex(self.bytes(n))

    def reseed(self, extra: bytes = b"") -> None:
        """Deterministic reseed using optional extra material (tests only)."""
        with self._lock:
            self._state.reseed(extra or b"test-reseed", reason="test")

    def status(self) -> dict[str, Any]:
        counters = self._state.public_counters()
        return {
            "state": self._state.status.name,
            "mode": "TestRNG",
            "seed": self._seed_repr,
            "reseed_count": counters.reseed_count,
            "bytes_generated": counters.bytes_generated,
            "generation_count": counters.generation_count,
            "uptime_seconds": uptime_seconds(counters.created_at),
        }

    def _experimental_state_snapshot(self) -> dict[str, object]:
        return self._state._experimental_snapshot()  # noqa: SLF001

    def _experimental_restore_state(self, snapshot: dict[str, object]) -> None:
        self._state._experimental_restore(snapshot)  # noqa: SLF001
