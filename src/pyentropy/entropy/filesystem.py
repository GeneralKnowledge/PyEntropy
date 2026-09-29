"""Filesystem entropy source.

Educational RNG — not a production CSPRNG.

Uses temporary file/directory metadata and operation timing.
Fails gracefully when the filesystem is unavailable.
Never uses secret file contents as an assumed entropy source.
"""

from __future__ import annotations

import os
import struct
import tempfile
import time

from pyentropy.entropy.base import EntropySource
from pyentropy.exceptions import EntropySourceError


class FilesystemEntropy(EntropySource):
    """Collect filesystem metadata and operation-timing observations."""

    name = "filesystem"

    def __init__(self, *, enabled: bool = True) -> None:
        self._enabled = enabled

    def collect(self) -> bytes:
        if not self._enabled:
            raise EntropySourceError("filesystem entropy source is disabled")

        buf = bytearray()
        t_start = time.perf_counter_ns()

        try:
            tmp = tempfile.mkdtemp(prefix="pyentropy_")
        except OSError as exc:
            raise EntropySourceError(f"cannot create temporary directory: {exc}") from exc

        try:
            t0 = time.perf_counter_ns()
            path = os.path.join(tmp, "probe.bin")
            with open(path, "wb") as fh:
                # Non-secret probe content: fixed pattern + timing nonce.
                fh.write(b"PYENTROPY-PROBE")
                fh.write(struct.pack(">Q", t0))
            t1 = time.perf_counter_ns()
            buf.extend(struct.pack(">Q", t1 - t0))

            st = os.stat(path)
            buf.extend(struct.pack(">Q", st.st_size))
            buf.extend(struct.pack(">d", st.st_mtime))
            buf.extend(struct.pack(">Q", int(getattr(st, "st_ino", 0))))
            buf.extend(struct.pack(">I", int(getattr(st, "st_dev", 0)) & 0xFFFFFFFF))

            t2 = time.perf_counter_ns()
            names = os.listdir(tmp)
            t3 = time.perf_counter_ns()
            buf.extend(struct.pack(">Q", t3 - t2))
            buf.extend(struct.pack(">H", len(names)))
            # Ordering of names can vary; include a fold of the names.
            fold = 0
            for name in names:
                for b in name.encode("utf-8", errors="replace"):
                    fold = ((fold << 5) - fold + b) & 0xFFFFFFFF
            buf.extend(struct.pack(">I", fold))

            try:
                dst = os.stat(tmp)
                buf.extend(struct.pack(">Q", int(getattr(dst, "st_ino", 0))))
            except OSError:
                buf.extend(b"\x00" * 8)

            os.remove(path)
        except OSError as exc:
            raise EntropySourceError(f"filesystem probe failed: {exc}") from exc
        finally:
            try:
                os.rmdir(tmp)
            except OSError:
                pass

        t_end = time.perf_counter_ns()
        buf.extend(struct.pack(">Q", t_end - t_start))
        buf.extend(struct.pack(">Q", time.monotonic_ns()))
        return bytes(buf)
