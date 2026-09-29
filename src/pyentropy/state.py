"""Generator state: secret material + public counters.

Educational RNG — not a production CSPRNG.

The secret state is NEVER exposed through status() or normal logging.
Experimental state-compromise tooling lives behind a private API.
"""

from __future__ import annotations

import struct
import threading
import time
from dataclasses import dataclass
from enum import Enum, auto

from pyentropy.conditioner import (
    DOMAIN_OUTPUT,
    DOMAIN_RESEED,
    DOMAIN_STATE_INIT,
    DOMAIN_STATE_UPDATE,
    Conditioner,
)


class GeneratorStatus(Enum):
    """Lifecycle status of the generator."""

    UNINITIALIZED = auto()
    READY = auto()


SECRET_STATE_SIZE: int = 32  # 256 bits
OUTPUT_BLOCK_SIZE: int = 32  # SHA-256 digest size


@dataclass
class PublicCounters:
    """Non-secret counters safe to expose via status()."""

    counter: int = 0
    generation_count: int = 0
    reseed_count: int = 0
    bytes_generated: int = 0
    created_at: float = 0.0
    last_reseed_at: float = 0.0
    last_reseed_reason: str = ""


class GeneratorState:
    """Hold secret state and drive hash-based output generation.

    Output construction::

        block = H(DOMAIN_OUTPUT || secret || counter)

    State evolution after each output *block*::

        secret' = H(DOMAIN_STATE_UPDATE || secret || counter || block)

    Partial blocks are buffered so request chunking does not change the stream.
    """

    def __init__(
        self,
        *,
        conditioner: Conditioner | None = None,
        secret_size: int = SECRET_STATE_SIZE,
    ) -> None:
        if secret_size < 32:
            raise ValueError("secret_size must be at least 32 bytes (256 bits)")
        self._conditioner = conditioner or Conditioner(digest_size=32)
        self._secret_size = secret_size
        self._secret: bytes = bytes(secret_size)
        self._counters = PublicCounters(created_at=time.monotonic())
        self._status = GeneratorStatus.UNINITIALIZED
        self._lock = threading.RLock()
        # Unused keystream from the last partial block — keeps chunked
        # reads identical to a single larger read.
        self._buffer = bytearray()

    @property
    def status(self) -> GeneratorStatus:
        return self._status

    @property
    def is_ready(self) -> bool:
        return self._status is GeneratorStatus.READY

    def initialize(self, seed_material: bytes) -> None:
        """Derive the initial secret state from conditioned seed material."""
        with self._lock:
            secret = self._conditioner.derive(
                DOMAIN_STATE_INIT,
                seed_material,
                size=self._secret_size,
            )
            self._secret = secret
            self._counters.counter = 0
            self._counters.generation_count = 0
            self._counters.reseed_count = 0
            self._counters.bytes_generated = 0
            self._buffer.clear()
            now = time.monotonic()
            self._counters.created_at = now
            self._counters.last_reseed_at = now
            self._counters.last_reseed_reason = "startup"
            self._status = GeneratorStatus.READY

    def reseed(self, pool_material: bytes, *, reason: str = "explicit") -> None:
        """Mix pool material into existing secret under DOMAIN_RESEED.

        New entropy is cryptographically combined with the existing
        secret — the state is never replaced by raw observations alone.
        """
        with self._lock:
            if self._status is not GeneratorStatus.READY:
                raise RuntimeError("cannot reseed an uninitialized generator")
            new_secret = self._conditioner.derive(
                DOMAIN_RESEED,
                self._secret,
                pool_material,
                struct.pack(">Q", self._counters.reseed_count),
                size=self._secret_size,
            )
            self._secret = new_secret
            self._counters.reseed_count += 1
            self._counters.last_reseed_at = time.monotonic()
            self._counters.last_reseed_reason = reason
            # Reset the output counter after reseed so counters don't
            # alone recount prior blocks under a new key.
            self._counters.counter = 0
            self._buffer.clear()

    def generate(self, n: int) -> bytes:
        """Generate *n* output bytes, evolving secret state after each block.

        Unused bytes from a partial final block are buffered so that
        ``generate(100)`` matches ``generate(40)+generate(35)+generate(25)``.
        """
        if n < 0:
            raise ValueError("n must be non-negative")
        if n == 0:
            return b""
        with self._lock:
            if self._status is not GeneratorStatus.READY:
                raise RuntimeError("generator is not READY")

            out = bytearray()
            # Drain any leftover keystream first.
            if self._buffer:
                take = min(n, len(self._buffer))
                out.extend(self._buffer[:take])
                del self._buffer[:take]

            while len(out) < n:
                block = self._output_block()
                self._counters.counter += 1
                self._evolve(block)
                need = n - len(out)
                if need >= len(block):
                    out.extend(block)
                else:
                    out.extend(block[:need])
                    self._buffer.extend(block[need:])

            result = bytes(out)
            self._counters.generation_count += 1
            self._counters.bytes_generated += n
            return result

    def _output_block(self) -> bytes:
        """Produce one OUTPUT-domain hash block for the current counter."""
        return self._conditioner.hash(
            DOMAIN_OUTPUT,
            self._secret,
            struct.pack(">Q", self._counters.counter),
        )

    def _evolve(self, output_block: bytes) -> None:
        """One-way state transition after producing one output block."""
        self._secret = self._conditioner.derive(
            DOMAIN_STATE_UPDATE,
            self._secret,
            struct.pack(">Q", self._counters.counter),
            output_block,
            size=self._secret_size,
        )

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
        """Capture secret state for educational compromise experiments.

        Do NOT call from application code.  Used only by
        experiments/adversarial_tests.py and related tooling.
        """
        with self._lock:
            return {
                "secret": bytes(self._secret),
                "counter": self._counters.counter,
                "generation_count": self._counters.generation_count,
                "reseed_count": self._counters.reseed_count,
                "bytes_generated": self._counters.bytes_generated,
                "buffer": bytes(self._buffer),
                "status": self._status.name,
            }

    def _experimental_restore(self, snapshot: dict[str, object]) -> None:
        """Restore a snapshot captured by ``_experimental_snapshot``."""
        with self._lock:
            secret = snapshot["secret"]
            if not isinstance(secret, (bytes, bytearray)):
                raise TypeError("snapshot secret must be bytes")
            self._secret = bytes(secret)
            self._counters.counter = int(snapshot["counter"])  # type: ignore[arg-type]
            self._counters.generation_count = int(snapshot["generation_count"])  # type: ignore[arg-type]
            self._counters.reseed_count = int(snapshot["reseed_count"])  # type: ignore[arg-type]
            self._counters.bytes_generated = int(snapshot["bytes_generated"])  # type: ignore[arg-type]
            buf = snapshot.get("buffer", b"")
            self._buffer = bytearray(buf if isinstance(buf, (bytes, bytearray)) else b"")
            status_name = snapshot.get("status", "READY")
            self._status = GeneratorStatus[str(status_name)]
