"""Scheduler / load entropy source.

Educational RNG — not a production CSPRNG.

Performs small workloads and records timing behaviour under the
current scheduler/load conditions.  Primarily experimental.
"""

from __future__ import annotations

import struct
import time

from pyentropy.entropy.base import EntropySource


class SchedulerEntropy(EntropySource):
    """Measure timing of short CPU bursts to observe scheduler effects."""

    name = "scheduler"

    def __init__(self, *, bursts: int = 16, spin: int = 5000) -> None:
        if bursts < 1:
            raise ValueError("bursts must be >= 1")
        if spin < 1:
            raise ValueError("spin must be >= 1")
        self._bursts = bursts
        self._spin = spin

    def collect(self) -> bytes:
        deltas: list[int] = []
        gaps: list[int] = []
        prev_end = time.perf_counter_ns()

        for i in range(self._bursts):
            # Yield-ish pause: sleep briefly then spin.
            time.sleep(0)
            t0 = time.perf_counter_ns()
            gaps.append(t0 - prev_end)
            acc = 0
            limit = self._spin + (i % 97)
            for j in range(limit):
                acc = (acc + j * j) & 0xFFFFFFFF
            t1 = time.perf_counter_ns()
            deltas.append(t1 - t0)
            # Prevent the loop from being optimised away in spirit.
            if acc == 0xDEADBEEF:
                deltas.append(acc)
            prev_end = t1

        buf = bytearray()
        buf.extend(struct.pack(">Q", time.perf_counter_ns()))
        buf.extend(struct.pack(">Q", time.monotonic_ns()))
        for d in deltas:
            buf.extend(struct.pack(">i", d & 0xFFFFFFFF))
        for g in gaps:
            buf.extend(struct.pack(">i", g & 0xFFFFFFFF))
        return bytes(buf)
