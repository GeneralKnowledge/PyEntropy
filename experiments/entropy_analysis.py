#!/usr/bin/env python3
"""Entropy laboratory: analyse individual entropy sources.

Educational only.  Statistical structure in observations is interesting
but does NOT prove cryptographic unpredictability.
"""

from __future__ import annotations

import argparse
import math
import statistics
import sys
from collections import Counter
from pathlib import Path

# Allow running without installation.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pyentropy.entropy import (  # noqa: E402
    FilesystemEntropy,
    ProcessEntropy,
    SchedulerEntropy,
    TimingEntropy,
)
from pyentropy.entropy.base import EntropySource  # noqa: E402


def bit_frequency(data: bytes) -> tuple[float, float]:
    if not data:
        return 0.0, 0.0
    ones = sum(bin(b).count("1") for b in data)
    total = len(data) * 8
    p1 = ones / total
    return 1.0 - p1, p1


def byte_frequency(data: bytes) -> Counter[int]:
    return Counter(data)


def runs_of_bits(data: bytes) -> list[int]:
    bits: list[int] = []
    for b in data:
        for i in range(8):
            bits.append((b >> (7 - i)) & 1)
    if not bits:
        return []
    runs: list[int] = []
    cur = 1
    for i in range(1, len(bits)):
        if bits[i] == bits[i - 1]:
            cur += 1
        else:
            runs.append(cur)
            cur = 1
    runs.append(cur)
    return runs


def autocorrelation(values: list[float], lag: int = 1) -> float:
    n = len(values)
    if n <= lag:
        return float("nan")
    mean = statistics.fmean(values)
    num = sum((values[i] - mean) * (values[i + lag] - mean) for i in range(n - lag))
    den = sum((v - mean) ** 2 for v in values)
    if den == 0:
        return float("nan")
    return num / den


def analyse_blob(label: str, blob: bytes) -> None:
    print(f"\n=== {label} ===")
    print(f"sample bytes:     {len(blob)}")
    if not blob:
        print("empty")
        return
    vals = list(blob)
    uniq = len(set(vals))
    print(f"unique byte vals: {uniq} / 256")
    print(f"min / max:        {min(vals)} / {max(vals)}")
    print(f"mean:             {statistics.fmean(vals):.4f}")
    if len(vals) > 1:
        print(f"variance:         {statistics.pvariance(vals):.4f}")
    p0, p1 = bit_frequency(blob)
    print(f"bit freq 0/1:     {p0:.4f} / {p1:.4f}")
    freq = byte_frequency(blob)
    top = freq.most_common(5)
    print(f"top byte freqs:   {top}")
    # Collision-ish: birthday among 4-byte windows
    windows = [blob[i : i + 4] for i in range(0, len(blob) - 3, 4)]
    if windows:
        collision_rate = 1.0 - (len(set(windows)) / len(windows))
        print(f"4-byte collision: {collision_rate:.4f} ({len(windows)} windows)")
    runs = runs_of_bits(blob)
    if runs:
        print(f"bit runs:         count={len(runs)} mean={statistics.fmean(runs):.3f} max={max(runs)}")
    ac = autocorrelation([float(v) for v in vals], lag=1)
    print(f"autocorr lag1:    {ac:.4f}")


def collect_many(source: EntropySource, n: int) -> bytes:
    chunks: list[bytes] = []
    for _ in range(n):
        try:
            chunks.append(source.collect())
        except Exception as exc:  # noqa: BLE001
            print(f"  ! {source.name} failed: {exc}")
    return b"".join(chunks)


def main() -> int:
    parser = argparse.ArgumentParser(description="PyEntropy entropy laboratory")
    parser.add_argument("--samples", type=int, default=64, help="collections per source")
    parser.add_argument(
        "--source",
        choices=["timing", "process", "filesystem", "scheduler", "all"],
        default="all",
    )
    args = parser.parse_args()

    print("PyEntropy entropy laboratory")
    print("NOTE: Statistical patterns ≠ cryptographic unpredictability.")
    print(f"Collecting {args.samples} samples per selected source...\n")

    sources: dict[str, EntropySource] = {
        "timing": TimingEntropy(rounds=16),
        "process": ProcessEntropy(),
        "filesystem": FilesystemEntropy(),
        "scheduler": SchedulerEntropy(bursts=8, spin=1000),
    }
    selected = list(sources.keys()) if args.source == "all" else [args.source]

    for name in selected:
        blob = collect_many(sources[name], args.samples)
        analyse_blob(name, blob)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
