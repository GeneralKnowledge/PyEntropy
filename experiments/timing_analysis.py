#!/usr/bin/env python3
"""Timing delta analysis for the timing entropy source.

Educational only.
"""

from __future__ import annotations

import argparse
import statistics
import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pyentropy.entropy import TimingEntropy  # noqa: E402


def extract_deltas(blob: bytes) -> list[int]:
    """Parse packed timing collect() output into signed 32-bit deltas."""
    if len(blob) < 16:
        return []
    # First 16 bytes are two uint64 timestamps.
    rest = blob[16:]
    deltas: list[int] = []
    for i in range(0, len(rest) - 3, 4):
        (d,) = struct.unpack(">i", rest[i : i + 4])
        deltas.append(d)
    return deltas


def main() -> int:
    parser = argparse.ArgumentParser(description="Timing entropy delta analysis")
    parser.add_argument("--rounds", type=int, default=64)
    parser.add_argument("--collections", type=int, default=32)
    args = parser.parse_args()

    src = TimingEntropy(rounds=args.rounds)
    all_deltas: list[int] = []
    for _ in range(args.collections):
        all_deltas.extend(extract_deltas(src.collect()))

    print("Timing delta analysis")
    print("Reminder: timing jitter is an observation, not certified entropy.\n")
    if not all_deltas:
        print("No deltas collected.")
        return 1

    print(f"count:    {len(all_deltas)}")
    print(f"unique:   {len(set(all_deltas))}")
    print(f"min/max:  {min(all_deltas)} / {max(all_deltas)}")
    print(f"mean:     {statistics.fmean(all_deltas):.3f}")
    print(f"stdev:    {statistics.pstdev(all_deltas):.3f}")
    # Low-bit histogram
    low8 = [d & 0xFF for d in all_deltas]
    print(f"low8 unique: {len(set(low8))} / 256")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
