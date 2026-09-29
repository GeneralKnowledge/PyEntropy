"""Entropy source base abstractions.

Educational RNG — not a production CSPRNG.

Sources produce *observations*, not certified entropy estimates.
A source must never declare "I contain N bits of entropy" as a trusted
fact — estimates are diagnostic only.
"""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class EntropySample:
    """One observation collected from an entropy source.

    Attributes
    ----------
    source_name:
        Identity of the source that produced this sample.
    raw:
        Raw observation bytes.  Treated as an observation, not as a
        certified entropy quantity.
    timestamp:
        Monotonic timestamp (``time.monotonic()``) when collected.
    metadata:
        Optional diagnostic key/value pairs (never secret state).
    """

    source_name: str
    raw: bytes
    timestamp: float
    metadata: dict[str, Any] = field(default_factory=dict)


class EntropySource(ABC):
    """Abstract interface for environmental observation sources."""

    name: str = "unnamed"

    @abstractmethod
    def collect(self) -> bytes:
        """Collect a raw observation.

        Raises
        ------
        Exception
            On failure.  Callers (the collector) must record failures
            rather than silently substituting predictable values.
        """

    def sample(self) -> EntropySample:
        """Collect and wrap an observation as an ``EntropySample``."""
        raw = self.collect()
        return EntropySample(
            source_name=self.name,
            raw=bytes(raw),
            timestamp=time.monotonic(),
            metadata={},
        )

    def available(self) -> bool:
        """Return True if a lightweight availability probe succeeds."""
        try:
            data = self.collect()
            return isinstance(data, (bytes, bytearray)) and len(data) > 0
        except Exception:
            return False
