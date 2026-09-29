"""Fixed-size entropy pool.

Educational RNG — not a production CSPRNG.

The pool holds approximately 512 bits (64 bytes) of mixed observation
material.  It never grows indefinitely; new samples are mixed into the
existing fixed-size state via the Conditioner.
"""

from __future__ import annotations

import struct
import time
from dataclasses import dataclass

from pyentropy.conditioner import DOMAIN_POOL_MIX, Conditioner


POOL_SIZE: int = 64  # 512 bits


@dataclass
class PoolDiagnostics:
    """Non-secret diagnostics for the entropy pool."""

    mix_count: int = 0
    bytes_mixed: int = 0
    sample_count: int = 0


class EntropyPool:
    """Fixed-size (64-byte) entropy pool.

    Mixing construction::

        pool_new = H(DOMAIN_POOL_MIX || pool_old || sample || metadata)

    where H is SHA-512 truncated/used to fill 64 bytes via the conditioner.
    """

    def __init__(
        self,
        *,
        size: int = POOL_SIZE,
        conditioner: Conditioner | None = None,
        initial: bytes | None = None,
    ) -> None:
        if size <= 0:
            raise ValueError("pool size must be positive")
        self._size = size
        # Use SHA-512 when pool is 64 bytes so one digest fills the pool.
        digest_size = 64 if size >= 64 else 32
        self._conditioner = conditioner or Conditioner(digest_size=digest_size)
        if initial is None:
            self._data = bytes(size)
        else:
            if len(initial) != size:
                raise ValueError(f"initial pool must be exactly {size} bytes")
            self._data = bytes(initial)
        self._diag = PoolDiagnostics()
        self._mix_counter = 0

    @property
    def size(self) -> int:
        return self._size

    def snapshot(self) -> bytes:
        """Return a copy of the current pool contents.

        Warning: for experiments / internal use only.  The pool contents
        are intermediate mixed material, not the generator secret state,
        but they should still not be logged in normal operation.
        """
        return bytes(self._data)

    def mix(self, sample: bytes, *, source_name: str = "", metadata: bytes = b"") -> None:
        """Mix an observation into the pool.

        Parameters
        ----------
        sample:
            Raw observation bytes from an entropy source.
        source_name:
            Identity of the source (preserved for domain mix metadata).
        metadata:
            Optional extra diagnostic bytes (not treated as secret).
        """
        # Defensive copy so callers cannot mutate after mix.
        sample = bytes(sample)
        meta = bytearray()
        meta.extend(struct.pack(">Q", self._mix_counter))
        meta.extend(struct.pack(">d", time.perf_counter()))
        meta.extend(source_name.encode("utf-8", errors="replace"))
        meta.extend(metadata)

        mixed = self._conditioner.derive(
            DOMAIN_POOL_MIX,
            self._data,
            sample,
            bytes(meta),
            size=self._size,
        )
        self._data = mixed
        self._mix_counter += 1
        self._diag.mix_count += 1
        self._diag.bytes_mixed += len(sample)
        self._diag.sample_count += 1

    def diagnostics(self) -> dict[str, int]:
        """Return non-secret pool diagnostics."""
        return {
            "pool_size": self._size,
            "mix_count": self._diag.mix_count,
            "bytes_mixed": self._diag.bytes_mixed,
            "sample_count": self._diag.sample_count,
        }
