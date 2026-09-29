"""Cryptographic conditioner: domain-separated hash mixing.

Educational RNG — not a production CSPRNG.

Domain separation ensures that hashing used for pool mixing cannot be
confused with hashing used for output generation, state updates, or
reseeding.  See docs/architecture.md.
"""

from __future__ import annotations

import hashlib
import struct
from typing import Final

# Domain-separation tags.  Each tag is a unique ASCII prefix so that
# H(DOMAIN_A || x) is never equal (by construction intent) to
# H(DOMAIN_B || x) for the same payload x under different roles.
DOMAIN_POOL_MIX: Final[bytes] = b"PyEntropy|POOL-MIX|v1"
DOMAIN_STATE_INIT: Final[bytes] = b"PyEntropy|STATE-INIT|v1"
DOMAIN_STATE_UPDATE: Final[bytes] = b"PyEntropy|STATE-UPDATE|v1"
DOMAIN_OUTPUT: Final[bytes] = b"PyEntropy|OUTPUT|v1"
DOMAIN_RESEED: Final[bytes] = b"PyEntropy|RESEED|v1"


def _length_prefix(data: bytes) -> bytes:
    """Encode *data* with a 4-byte big-endian length prefix."""
    return struct.pack(">I", len(data)) + data


class Conditioner:
    """Provide cryptographic mixing via SHA-256 or SHA-512.

    The conditioner is intentionally independent of entropy sources.
    It only knows how to hash tagged inputs into a fixed-size digest.
    """

    def __init__(self, *, digest_size: int = 32) -> None:
        if digest_size not in (32, 64):
            raise ValueError("digest_size must be 32 (SHA-256) or 64 (SHA-512)")
        self._digest_size = digest_size
        self._hash_name = "sha256" if digest_size == 32 else "sha512"

    @property
    def digest_size(self) -> int:
        return self._digest_size

    def hash(self, domain: bytes, *parts: bytes) -> bytes:
        """Hash domain-separated parts into a digest of ``digest_size`` bytes."""
        h = hashlib.new(self._hash_name)
        h.update(_length_prefix(domain))
        for part in parts:
            h.update(_length_prefix(part))
        return h.digest()

    def mix(self, state: bytes, data: bytes, *, domain: bytes = DOMAIN_POOL_MIX) -> bytes:
        """Mix *data* into *state* under *domain*; return new fixed-size state."""
        return self.hash(domain, state, data)

    def derive(self, domain: bytes, *parts: bytes, size: int | None = None) -> bytes:
        """Derive *size* bytes (default: digest_size) from tagged inputs.

        When *size* exceeds one digest, expand with a counter construction
        still under the same domain tag.
        """
        target = self._digest_size if size is None else size
        if target < 0:
            raise ValueError("size must be non-negative")
        if target == 0:
            return b""

        out = bytearray()
        counter = 0
        while len(out) < target:
            block = self.hash(domain, *parts, struct.pack(">Q", counter))
            out.extend(block)
            counter += 1
        return bytes(out[:target])
