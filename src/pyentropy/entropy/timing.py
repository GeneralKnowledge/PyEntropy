"""Timing-jitter entropy source.

Educational RNG — not a production CSPRNG.

IMPORTANT: Timing deltas are *observations*.  Not every bit of a
timestamp or delta is unpredictable.  Virtualised environments, quiet
systems, and coarse timers can produce highly correlated deltas.
Treat this source as experimental diversification material.
"""

from __future__ import annotations

import hashlib
import os
import struct
import time

# os is used only for filesystem metadata probes (stat/listdir), never as an RNG.

from collections.abc import Callable

from pyentropy.entropy.base import EntropySource


class TimingEntropy(EntropySource):
    """Collect timing deltas from small workloads.

    Observations include arithmetic, memory/object creation, hashing,
    and optional filesystem metadata access — recording deltas, not
    absolute wall-clock time alone.
    """

    name = "timing"

    def __init__(self, *, rounds: int = 32, include_fs: bool = True) -> None:
        if rounds < 1:
            raise ValueError("rounds must be >= 1")
        self._rounds = rounds
        self._include_fs = include_fs

    def collect(self) -> bytes:
        deltas: list[int] = []
        deltas.extend(self._arith_deltas())
        deltas.extend(self._memory_deltas())
        deltas.extend(self._hash_deltas())
        deltas.extend(self._object_deltas())
        if self._include_fs:
            deltas.extend(self._fs_meta_deltas())

        # Pack deltas + a coarse mix of both clock domains.
        buf = bytearray()
        buf.extend(struct.pack(">Q", time.perf_counter_ns()))
        buf.extend(struct.pack(">Q", time.monotonic_ns()))
        for d in deltas:
            # Keep low bits; high bits of large deltas are often predictable.
            buf.extend(struct.pack(">i", d & 0xFFFFFFFF))
        return bytes(buf)

    def _timed(self, op: Callable[[], None]) -> int:
        t0 = time.perf_counter_ns()
        op()
        t1 = time.perf_counter_ns()
        return t1 - t0

    def _arith_deltas(self) -> list[int]:
        out: list[int] = []
        acc = 1
        for i in range(self._rounds):

            def _op(i: int = i, acc_ref: list[int] = [acc]) -> None:
                x = acc_ref[0]
                for j in range(50 + (i % 7)):
                    x = (x * 1103515245 + 12345 + j) & 0xFFFFFFFF
                acc_ref[0] = x

            out.append(self._timed(_op))
        return out

    def _memory_deltas(self) -> list[int]:
        out: list[int] = []
        for i in range(max(4, self._rounds // 4)):

            def _op(i: int = i) -> None:
                buf = bytearray(256 + (i % 64))
                for j in range(len(buf)):
                    buf[j] = (j * 17 + i) & 0xFF
                _ = sum(buf)

            out.append(self._timed(_op))
        return out

    def _hash_deltas(self) -> list[int]:
        out: list[int] = []
        for i in range(max(4, self._rounds // 4)):

            def _op(i: int = i) -> None:
                h = hashlib.sha256()
                h.update(struct.pack(">Q", i))
                # Deterministic input for the timed hash operation itself.
                h.update(b"pyentropy-timing" * (1 + (i % 3)))
                _ = h.digest()

            out.append(self._timed(_op))
        return out

    def _object_deltas(self) -> list[int]:
        out: list[int] = []
        for i in range(max(4, self._rounds // 4)):

            def _op(i: int = i) -> None:
                objs = [{k: k * i} for k in range(20 + (i % 5))]
                _ = len(objs) + sum(next(iter(o.values())) for o in objs)

            out.append(self._timed(_op))
        return out

    def _fs_meta_deltas(self) -> list[int]:
        out: list[int] = []
        try:

            def _op() -> None:
                _ = os.stat(".")
                _ = os.listdir(".")

            out.append(self._timed(_op))
        except OSError:
            pass
        return out
