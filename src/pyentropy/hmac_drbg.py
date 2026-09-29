"""HMAC-DRBG (NIST SP 800-90A) implemented with stdlib ``hmac`` / ``hashlib``.

Educational RNG — not a production CSPRNG certification.

This module implements the HMAC_DRBG *construction* ourselves.  We use
Python's standard-library HMAC primitive the same way the pool uses
SHA-2: as a building block, not as a wrapped RNG (``random``,
``secrets``, ``os.urandom``, OpenSSL RAND, … are not used here).

Reference: NIST SP 800-90A Rev. 1, §10.1.2 (HMAC_DRBG).
"""

from __future__ import annotations

import hashlib
import hmac
from typing import Final


# SP 800-90A suggests a large reseed interval; we keep a generous default
# for education.  PyEntropy's *policy* layer (bytes/time) reseeds earlier.
DEFAULT_RESEED_INTERVAL: Final[int] = 2**48


class HmacDrbg:
    """HMAC-DRBG with SHA-256 (outlen = 256 bits).

    Internal secret state is ``(Key, V)`` plus ``reseed_counter``.
    Never expose Key/V through normal diagnostics.
    """

    def __init__(self, *, hash_name: str = "sha256") -> None:
        if hash_name not in hashlib.algorithms_available and hash_name not in (
            "sha256",
            "sha512",
            "sha384",
            "sha1",
        ):
            raise ValueError(f"unsupported hash: {hash_name}")
        self._hash_name = hash_name
        self._outlen = hashlib.new(hash_name).digest_size
        self._key = bytes(self._outlen)  # set properly in instantiate()
        self._v = bytes(self._outlen)
        self._reseed_counter = 0
        self._instantiated = False

    @property
    def outlen(self) -> int:
        """Output block size in bytes (HMAC digest length)."""
        return self._outlen

    @property
    def reseed_counter(self) -> int:
        return self._reseed_counter

    @property
    def instantiated(self) -> bool:
        return self._instantiated

    def _hmac(self, key: bytes, data: bytes) -> bytes:
        return hmac.new(key, data, self._hash_name).digest()

    def update(self, provided_data: bytes = b"") -> None:
        """HMAC_DRBG_Update (SP 800-90A §10.1.2.2).

        Mixes optional ``provided_data`` into ``(Key, V)``.  Always
        advances Key/V; when ``provided_data`` is non-empty, a second
        keyed update incorporates that material.
        """
        # K = HMAC(K, V || 0x00 || provided_data)
        self._key = self._hmac(self._key, self._v + b"\x00" + provided_data)
        # V = HMAC(K, V)
        self._v = self._hmac(self._key, self._v)
        if provided_data:
            # K = HMAC(K, V || 0x01 || provided_data)
            self._key = self._hmac(self._key, self._v + b"\x01" + provided_data)
            # V = HMAC(K, V)
            self._v = self._hmac(self._key, self._v)

    def instantiate(
        self,
        entropy_input: bytes,
        *,
        nonce: bytes = b"",
        personalization_string: bytes = b"",
    ) -> None:
        """HMAC_DRBG_Instantiate (§10.1.2.3).

        ``seed_material = entropy_input || nonce || personalization_string``
        """
        if not entropy_input:
            raise ValueError("entropy_input must be non-empty")
        seed_material = entropy_input + nonce + personalization_string
        # Key = 0x00…00, V = 0x01…01  (each outlen bytes)
        self._key = bytes(self._outlen)
        self._v = b"\x01" * self._outlen
        self.update(seed_material)
        self._reseed_counter = 1
        self._instantiated = True

    def reseed(
        self,
        entropy_input: bytes,
        *,
        additional_input: bytes = b"",
    ) -> None:
        """HMAC_DRBG_Reseed (§10.1.2.4).

        New entropy is mixed into the *existing* ``(Key, V)`` via Update —
        raw observations never replace the state by themselves.
        """
        if not self._instantiated:
            raise RuntimeError("DRBG is not instantiated")
        if not entropy_input:
            raise ValueError("entropy_input must be non-empty")
        self.update(entropy_input + additional_input)
        self._reseed_counter = 1

    def generate(
        self,
        n: int,
        *,
        additional_input: bytes = b"",
        reseed_interval: int = DEFAULT_RESEED_INTERVAL,
    ) -> bytes:
        """HMAC_DRBG_Generate (§10.1.2.5).

        Returns *n* bytes.  After producing output, Update is always run
        so the state moves forward (educational backtracking resistance).

        Note: NIST updates once per ``generate`` call.  Therefore
        ``generate(100)`` is **not** required to equal
        ``generate(40) + generate(60)`` — each call reseeds the working
        state via Update at the end.
        """
        if not self._instantiated:
            raise RuntimeError("DRBG is not instantiated")
        if n < 0:
            raise ValueError("n must be non-negative")
        if n == 0:
            return b""
        if self._reseed_counter > reseed_interval:
            raise RuntimeError("reseed required (HMAC-DRBG reseed_interval exceeded)")

        if additional_input:
            self.update(additional_input)

        temp = bytearray()
        while len(temp) < n:
            self._v = self._hmac(self._key, self._v)
            temp.extend(self._v)

        result = bytes(temp[:n])
        # Always Update after generate (additional_input may be empty).
        self.update(additional_input)
        self._reseed_counter += 1
        return result

    # ------------------------------------------------------------------
    # Experimental-only access
    # ------------------------------------------------------------------

    def _experimental_snapshot(self) -> dict[str, object]:
        """Capture (Key, V, reseed_counter) for compromise labs only."""
        return {
            "key": bytes(self._key),
            "v": bytes(self._v),
            "reseed_counter": self._reseed_counter,
            "hash_name": self._hash_name,
            "instantiated": self._instantiated,
        }

    def _experimental_restore(self, snapshot: dict[str, object]) -> None:
        key = snapshot["key"]
        v = snapshot["v"]
        if not isinstance(key, (bytes, bytearray)) or not isinstance(v, (bytes, bytearray)):
            raise TypeError("snapshot key/v must be bytes")
        if len(key) != self._outlen or len(v) != self._outlen:
            raise ValueError("snapshot key/v length mismatch")
        self._key = bytes(key)
        self._v = bytes(v)
        self._reseed_counter = int(snapshot["reseed_counter"])  # type: ignore[arg-type]
        self._instantiated = bool(snapshot.get("instantiated", True))
