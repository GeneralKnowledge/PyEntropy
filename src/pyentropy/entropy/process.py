"""Process / environment entropy source.

Educational RNG — not a production CSPRNG.

Process identifiers, paths, and environment fingerprints primarily
provide *state diversification*.  Do not assume they contain strong
entropy — many values are predictable or slowly changing.
"""

from __future__ import annotations

import os
import struct
import sys
import threading
import time

from pyentropy.entropy.base import EntropySource


class ProcessEntropy(EntropySource):
    """Collect process- and environment-state observations."""

    name = "process"

    def collect(self) -> bytes:
        buf = bytearray()
        buf.extend(struct.pack(">i", os.getpid()))
        try:
            buf.extend(struct.pack(">i", os.getppid()))
        except AttributeError:
            buf.extend(struct.pack(">i", 0))

        buf.extend(struct.pack(">Q", threading.get_ident()))
        buf.extend(struct.pack(">Q", time.perf_counter_ns()))
        buf.extend(struct.pack(">Q", time.monotonic_ns()))
        buf.extend(struct.pack(">Q", time.time_ns() if hasattr(time, "time_ns") else int(time.time() * 1e9)))

        cwd = os.getcwd().encode("utf-8", errors="replace")
        buf.extend(struct.pack(">H", len(cwd)))
        buf.extend(cwd)

        try:
            st = os.stat(".")
            buf.extend(struct.pack(">Q", int(getattr(st, "st_ino", 0))))
            buf.extend(struct.pack(">d", float(getattr(st, "st_mtime", 0.0))))
        except OSError:
            buf.extend(b"\x00" * 16)

        # Environment fingerprint: sorted key names only (not values —
        # values may contain secrets and must not be logged/stored raw).
        keys = sorted(os.environ.keys())
        key_blob = ",".join(keys).encode("utf-8", errors="replace")
        # Hash-length bound: include length + truncated key list hash-like mix.
        buf.extend(struct.pack(">H", len(keys)))
        buf.extend(struct.pack(">I", len(key_blob)))
        # Mix key names via simple rolling xor-fold to avoid storing secrets.
        fold = 0
        for b in key_blob:
            fold = ((fold << 5) - fold + b) & 0xFFFFFFFF
        buf.extend(struct.pack(">I", fold))

        buf.extend(struct.pack(">H", sys.version_info.major))
        buf.extend(struct.pack(">H", sys.version_info.minor))
        buf.extend(struct.pack(">H", sys.version_info.micro))
        buf.extend(sys.platform.encode("ascii", errors="replace")[:16].ljust(16, b"\x00"))

        # Allocation behaviour observation (timing of small allocations).
        t0 = time.perf_counter_ns()
        blobs = [bytearray(64) for _ in range(32)]
        t1 = time.perf_counter_ns()
        buf.extend(struct.pack(">Q", t1 - t0))
        buf.extend(struct.pack(">I", sum(len(b) for b in blobs)))

        return bytes(buf)
