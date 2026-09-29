#!/usr/bin/env python3
"""Distribution tests on PyEntropy generator output.

IMPORTANT: Passing statistical tests does NOT establish cryptographic
security.  Biased or predictable generators can still pass many tests;
failing tests only shows statistical structure, not a full security proof.
"""

from __future__ import annotations

import argparse
import math
import statistics
import sys
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pyentropy import RNG  # noqa: E402


def bit_balance(data: bytes) -> tuple[float, float]:
    ones = sum(bin(b).count("1") for b in data)
    total = len(data) * 8
    p1 = ones / total
    return 1.0 - p1, p1


def runs(data: bytes) -> list[int]:
    bits: list[int] = []
    for b in data:
        for i in range(8):
            bits.append((b >> (7 - i)) & 1)
    out: list[int] = []
    cur = 1
    for i in range(1, len(bits)):
        if bits[i] == bits[i - 1]:
            cur += 1
        else:
            out.append(cur)
            cur = 1
    if bits:
        out.append(cur)
    return out


def repeated_blocks(data: bytes, size: int = 16) -> int:
    blocks = [data[i : i + size] for i in range(0, len(data) - size + 1, size)]
    return len(blocks) - len(set(blocks))


def hamming(a: bytes, b: bytes) -> int:
    return sum(bin(x ^ y).count("1") for x, y in zip(a, b, strict=True))


def serial_correlation(data: bytes) -> float:
    if len(data) < 2:
        return float("nan")
    xs = [float(b) for b in data]
    mean = statistics.fmean(xs)
    num = sum((xs[i] - mean) * (xs[i + 1] - mean) for i in range(len(xs) - 1))
    den = sum((x - mean) ** 2 for x in xs)
    return num / den if den else float("nan")


def chi_square_bytes(data: bytes) -> float:
    freq = Counter(data)
    n = len(data)
    expected = n / 256
    return sum(((freq.get(i, 0) - expected) ** 2) / expected for i in range(256))


def main() -> int:
    parser = argparse.ArgumentParser(description="PyEntropy distribution tests")
    parser.add_argument("--bytes", type=int, default=100_000)
    args = parser.parse_args()

    print("=" * 60)
    print("PyEntropy distribution tests")
    print("Passing these tests does NOT establish cryptographic security.")
    print("=" * 60)

    rng = RNG()
    data = rng.bytes(args.bytes)
    print(f"\nGenerated {len(data)} bytes\n")

    p0, p1 = bit_balance(data)
    print(f"Bit balance:     0={p0:.4%}  1={p1:.4%}")

    freq = Counter(data)
    print(f"Byte values seen: {len(freq)} / 256")
    print(f"Byte chi-square:  {chi_square_bytes(data):.2f} (df=255, ~255 expected)")

    r = runs(data)
    print(f"Bit runs:         n={len(r)} mean={statistics.fmean(r):.3f} max={max(r)}")

    print(f"Repeated 16B:     {repeated_blocks(data, 16)}")

    blocks = [rng.bytes(32) for _ in range(20)]
    distances = [hamming(blocks[i], blocks[i + 1]) for i in range(len(blocks) - 1)]
    print(f"Hamming (32B):    mean={statistics.fmean(distances):.1f} (ideal ~128)")

    print(f"Serial corr:      {serial_correlation(data):.6f}")
    print("\nDone. Interpret cautiously — stats ≠ security.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
