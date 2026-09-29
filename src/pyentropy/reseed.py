"""Reseed policy and orchestration.

Educational RNG — not a production CSPRNG.

Default thresholds (1 MiB generated OR 60 seconds) are experimental
tuning knobs, not security guarantees.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from pyentropy.entropy.composite import EntropyCollector
from pyentropy.state import GeneratorState


# Experimental defaults — NOT security guarantees.
DEFAULT_RESEED_BYTES: int = 1 * 1024 * 1024  # 1 MiB
DEFAULT_RESEED_SECONDS: float = 60.0


@dataclass
class ReseedPolicy:
    """Configurable reseed triggers."""

    byte_threshold: int = DEFAULT_RESEED_BYTES
    time_threshold: float = DEFAULT_RESEED_SECONDS

    def should_reseed(self, state: GeneratorState) -> tuple[bool, str]:
        """Return (needed, reason) based on public counters."""
        counters = state.public_counters()
        if counters.bytes_generated > 0 and counters.bytes_generated >= self.byte_threshold:
            # Compare bytes since last reseed approximately via total
            # generated vs threshold — for educational clarity we reseed
            # when total generated crosses multiples of the threshold
            # from the last reseed marker stored on the policy consumer.
            return True, "byte_threshold"
        elapsed = time.monotonic() - counters.last_reseed_at
        if elapsed >= self.time_threshold:
            return True, "time_threshold"
        return False, ""


class ReseedController:
    """Collect fresh observations and reseed the generator state."""

    def __init__(
        self,
        collector: EntropyCollector,
        state: GeneratorState,
        *,
        policy: ReseedPolicy | None = None,
    ) -> None:
        self._collector = collector
        self._state = state
        self._policy = policy or ReseedPolicy()
        self._bytes_since_reseed = 0

    @property
    def policy(self) -> ReseedPolicy:
        return self._policy

    def note_generated(self, n: int) -> None:
        """Track bytes produced since the last reseed."""
        self._bytes_since_reseed += n

    def maybe_reseed(self) -> bool:
        """Reseed if policy thresholds are met.  Return True if reseeding occurred."""
        if self._bytes_since_reseed >= self._policy.byte_threshold:
            self.reseed(reason="byte_threshold")
            return True
        counters = self._state.public_counters()
        elapsed = time.monotonic() - counters.last_reseed_at
        if elapsed >= self._policy.time_threshold:
            self.reseed(reason="time_threshold")
            return True
        return False

    def reseed(self, *, reason: str = "explicit", rounds: int = 2) -> None:
        """Collect observations, mix into pool, and reseed generator state.

        Construction::

            new_secret = H(DOMAIN_RESEED || old_secret || pool || reseed_count)
        """
        for _ in range(rounds):
            self._collector.collect_once()
        pool_material = self._collector.pool.snapshot()
        self._state.reseed(pool_material, reason=reason)
        self._bytes_since_reseed = 0
