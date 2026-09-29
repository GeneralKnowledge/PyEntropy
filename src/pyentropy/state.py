"""Generator state wrapping HMAC-DRBG.

Educational RNG — not a production CSPRNG.

The secret DRBG state ``(Key, V)`` is NEVER exposed through status() or
normal logging.  Experimental state-compromise tooling lives behind a
private API.
"""

from __future__ import annotations

import struct
import threading
import time
from dataclasses import dataclass
from enum import Enum, auto

from pyentropy.hmac_drbg import HmacDrbg


class GeneratorStatus(Enum):
    """Lifecycle status of the generator."""

    UNINITIALIZED = auto()
    READY = auto()


# Personalization strings — educational domain tags for Instantiate.
PERSONALIZATION_RNG: bytes = b"PyEntropy|HMAC-DRBG|RNG|v1"
PERSONALIZATION_TEST: bytes = b"PyEntropy|HMAC-DRBG|TestRNG|v1"


@dataclass
class PublicCounters:
    """Non-secret counters safe to expose via status()."""

    counter: int = 0  # maps to HMAC-DRBG reseed_counter (generate calls)
    generation_count: int = 0
    reseed_count: int = 0
    bytes_generated: int = 0
    created_at: float = 0.0
    last_reseed_at: float = 0.0
    last_reseed_reason: str = ""


class GeneratorState:
    """Drive output via HMAC-DRBG; keep public counters for diagnostics.

    Construction (NIST SP 800-90A HMAC_DRBG)::

        Instantiate(entropy_input, nonce, personalization)
        Generate(n) → bytes, then Update (state evolution)
        Reseed(entropy_input) → Update mixes new material into (Key, V)

    The entropy *pool* still feeds ``entropy_input``; this class does not
    collect observations itself.
    """

    def __init__(
        self,
        *,
        hash_name: str = "sha256",
        personalization: bytes = PERSONALIZATION_RNG,
    ) -> None:
        self._drbg = HmacDrbg(hash_name=hash_name)
        self._personalization = bytes(personalization)
        self._counters = PublicCounters(created_at=time.monotonic())
        self._status = GeneratorStatus.UNINITIALIZED
        self._lock = threading.RLock()

    @property
    def status(self) -> GeneratorStatus:
        return self._status

    @property
    def is_ready(self) -> bool:
        return self._status is GeneratorStatus.READY

    def initialize(self, seed_material: bytes, *, nonce: bytes = b"") -> None:
        """Instantiate the HMAC-DRBG from conditioned pool material."""
        with self._lock:
            # Nonce diversifies Instantiate when provided (e.g. reseed count).
            self._drbg.instantiate(
                seed_material,
                nonce=nonce,
                personalization_string=self._personalization,
            )
            self._counters.counter = self._drbg.reseed_counter
            self._counters.generation_count = 0
            self._counters.reseed_count = 0
            self._counters.bytes_generated = 0
            now = time.monotonic()
            self._counters.created_at = now
            self._counters.last_reseed_at = now
            self._counters.last_reseed_reason = "startup"
            self._status = GeneratorStatus.READY

    def reseed(self, pool_material: bytes, *, reason: str = "explicit") -> None:
        """Reseed HMAC-DRBG with pool material mixed into existing (Key, V)."""
        with self._lock:
            if self._status is not GeneratorStatus.READY:
                raise RuntimeError("cannot reseed an uninitialized generator")
            additional = struct.pack(">Q", self._counters.reseed_count)
            self._drbg.reseed(pool_material, additional_input=additional)
            self._counters.reseed_count += 1
            self._counters.last_reseed_at = time.monotonic()
            self._counters.last_reseed_reason = reason
            self._counters.counter = self._drbg.reseed_counter

    def generate(self, n: int) -> bytes:
        """Generate *n* bytes via HMAC-DRBG_Generate."""
        if n < 0:
            raise ValueError("n must be non-negative")
        if n == 0:
            return b""
        with self._lock:
            if self._status is not GeneratorStatus.READY:
                raise RuntimeError("generator is not READY")
            result = self._drbg.generate(n)
            self._counters.generation_count += 1
            self._counters.bytes_generated += n
            self._counters.counter = self._drbg.reseed_counter
            return result

    def public_counters(self) -> PublicCounters:
        """Return a copy of non-secret counters."""
        with self._lock:
            c = self._counters
            return PublicCounters(
                counter=c.counter,
                generation_count=c.generation_count,
                reseed_count=c.reseed_count,
                bytes_generated=c.bytes_generated,
                created_at=c.created_at,
                last_reseed_at=c.last_reseed_at,
                last_reseed_reason=c.last_reseed_reason,
            )

    # ------------------------------------------------------------------
    # Experimental-only state access (NOT part of the public API)
    # ------------------------------------------------------------------

    def _experimental_snapshot(self) -> dict[str, object]:
        """Capture DRBG state for educational compromise experiments."""
        with self._lock:
            snap = self._drbg._experimental_snapshot()  # noqa: SLF001
            snap.update(
                {
                    "generation_count": self._counters.generation_count,
                    "reseed_count": self._counters.reseed_count,
                    "bytes_generated": self._counters.bytes_generated,
                    "status": self._status.name,
                    # Compatibility alias used by older experiment text:
                    "secret": snap["key"],
                }
            )
            return snap

    def _experimental_restore(self, snapshot: dict[str, object]) -> None:
        """Restore a snapshot captured by ``_experimental_snapshot``."""
        with self._lock:
            self._drbg._experimental_restore(snapshot)  # noqa: SLF001
            self._counters.counter = self._drbg.reseed_counter
            self._counters.generation_count = int(snapshot["generation_count"])  # type: ignore[arg-type]
            self._counters.reseed_count = int(snapshot["reseed_count"])  # type: ignore[arg-type]
            self._counters.bytes_generated = int(snapshot["bytes_generated"])  # type: ignore[arg-type]
            status_name = snapshot.get("status", "READY")
            self._status = GeneratorStatus[str(status_name)]
