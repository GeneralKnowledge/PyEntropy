#!/usr/bin/env python3
"""Simple performance benchmark for PyEntropy.

Understanding cost is the goal — not beating OS RNGs.
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pyentropy import RNG, TestRNG  # noqa: E402
from pyentropy.conditioner import DOMAIN_POOL_MIX, Conditioner  # noqa: E402
from pyentropy.entropy import TimingEntropy  # noqa: E402
from pyentropy.pool import EntropyPool  # noqa: E402


def bench(label: str, fn, repeats: int = 3) -> None:  # noqa: ANN001
    times: list[float] = []
    for _ in range(repeats):
        t0 = time.perf_counter()
        fn()
        times.append(time.perf_counter() - t0)
    best = min(times)
    print(f"{label:<40} {best*1000:10.3f} ms")


def main() -> int:
    parser = argparse.ArgumentParser(description="PyEntropy benchmarks")
    args = parser.parse_args()
    _ = args

    print("PyEntropy benchmarks (best of 3)\n")

    rng = RNG()
    test = TestRNG(b"bench")

    for n, label in [
        (1, "1 byte"),
        (32, "32 bytes"),
        (1024, "1 KB"),
        (1024 * 1024, "1 MB"),
    ]:
        bench(f"RNG.bytes({label})", lambda n=n: rng.bytes(n))
        bench(f"TestRNG.bytes({label})", lambda n=n: test.bytes(n))

    # Component costs
    src = TimingEntropy(rounds=16)
    bench("timing collect()", lambda: src.collect())

    cond = Conditioner(digest_size=32)
    state = b"\x00" * 32
    data = b"\x11" * 64
    bench("conditioner.mix()", lambda: cond.mix(state, data, domain=DOMAIN_POOL_MIX))

    pool = EntropyPool()
    bench("pool.mix(64B)", lambda: pool.mix(b"\x22" * 64, source_name="bench"))

    bench("rng.reseed()", lambda: rng.reseed())

    # Throughput estimate for 1 MB
    t0 = time.perf_counter()
    rng.bytes(1024 * 1024)
    dt = time.perf_counter() - t0
    print(f"\nApprox RNG throughput (1 MiB): {1.0 / dt:.2f} MiB/s")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
