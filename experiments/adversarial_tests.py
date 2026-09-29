#!/usr/bin/env python3
"""Adversarial and state-compromise experiments.

Educational investigations.  Surviving these experiments does NOT prove
security.  Failing them reveals concrete weaknesses in assumptions.
"""

from __future__ import annotations

import os
import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from pyentropy import RNG, TestRNG  # noqa: E402
from pyentropy.entropy import (  # noqa: E402
    ConstantEntropy,
    CounterEntropy,
    FailingEntropy,
    FilesystemEntropy,
    ProcessEntropy,
    RepeatingEntropy,
    SchedulerEntropy,
    TimingEntropy,
)
from pyentropy.exceptions import InitializationError  # noqa: E402


def banner(title: str) -> None:
    print("\n" + "=" * 60)
    print(title)
    print("=" * 60)


def exp_all_predictable() -> None:
    banner("1. All sources predictable")
    rng = RNG(
        sources=[
            ConstantEntropy(b"\x00" * 64),
            CounterEntropy(),
            RepeatingEntropy(b"XY"),
        ]
    )
    a = rng.bytes(32)
    b = rng.bytes(32)
    print(f"output A: {a.hex()}")
    print(f"output B: {b.hex()}")
    print(f"A != B:   {a != b}  (state evolution still changes output)")
    print("Lesson: predictable inputs still yield changing output via")
    print("HMAC-DRBG, but an attacker who models the inputs may predict it.")


def exp_one_predictable() -> None:
    banner("2. One source predictable, others normal")
    rng = RNG(
        sources=[
            TimingEntropy(rounds=8),
            ProcessEntropy(),
            ConstantEntropy(b"\xff" * 64),
        ]
    )
    print(f"status sources: {list(rng.status()['sources'])}")
    print(f"sample: {rng.hex(16)}")


def exp_one_zero() -> None:
    banner("3. One source constantly zero")
    rng = RNG(
        sources=[
            TimingEntropy(rounds=8),
            ConstantEntropy(b"\x00" * 64),
            ProcessEntropy(),
        ]
    )
    print(f"bytes: {rng.hex(16)}")


def exp_one_unavailable() -> None:
    banner("4. One source unavailable")
    rng = RNG(
        sources=[
            TimingEntropy(rounds=8),
            FailingEntropy("disk gone"),
            ProcessEntropy(),
        ]
    )
    st = rng.status()
    print(f"failures: {st['source_failures']}")
    print(f"failing active: {st['sources'].get('failing', {})}")
    print(f"sample: {rng.hex(16)}")


def exp_timing_disabled() -> None:
    banner("5. Timing source disabled (omitted)")
    rng = RNG(sources=[ProcessEntropy(), FilesystemEntropy(), SchedulerEntropy(bursts=4)])
    print(f"sources: {list(rng.status()['sources'])}")
    print(f"sample: {rng.hex(16)}")


def exp_filesystem_disabled() -> None:
    banner("6. Filesystem source disabled")
    rng = RNG(
        sources=[
            TimingEntropy(rounds=8),
            ProcessEntropy(),
            FilesystemEntropy(enabled=False),
            SchedulerEntropy(bursts=4),
        ]
    )
    st = rng.status()
    fs = st["sources"].get("filesystem", {})
    print(f"filesystem: {fs}")
    print(f"sample: {rng.hex(16)}")


def exp_cpu_load() -> None:
    banner("7. Heavy CPU load (brief)")
    stop = threading.Event()

    def burner() -> None:
        x = 0
        while not stop.is_set():
            x = (x * 1103515245 + 12345) & 0xFFFFFFFF

    threads = [threading.Thread(target=burner, daemon=True) for _ in range(4)]
    for t in threads:
        t.start()
    time.sleep(0.05)
    rng = RNG(sources=[TimingEntropy(rounds=16), SchedulerEntropy(bursts=8)])
    print(f"under load: {rng.hex(16)}")
    stop.set()
    for t in threads:
        t.join(timeout=1)


def exp_idle() -> None:
    banner("8. Idle machine (best-effort)")
    time.sleep(0.05)
    rng = RNG(sources=[TimingEntropy(rounds=16), SchedulerEntropy(bursts=8)])
    print(f"idle-ish: {rng.hex(16)}")


def exp_multiple_instances() -> None:
    banner("9. Multiple RNG instances")
    outputs = [RNG().bytes(16) for _ in range(5)]
    unique = len(set(outputs))
    print(f"unique among 5 instances: {unique}/5")


def exp_fork() -> None:
    banner("10. Fork / process experiment")
    if not hasattr(os, "fork"):
        print("os.fork unavailable on this platform; skipped.")
        return

    rng = RNG()
    parent_before = rng.bytes(16)
    pid = os.fork()
    if pid == 0:
        # Child
        child_out = rng.bytes(16)
        # Write to a temp-ish pipe via exit code is awkward; print and _exit.
        sys.stdout.write(f"CHILD {child_out.hex()}\n")
        sys.stdout.flush()
        os._exit(0)
    else:
        # Parent
        parent_after = rng.bytes(16)
        _pid, status = os.waitpid(pid, 0)
        print(f"parent before fork: {parent_before.hex()}")
        print(f"parent after fork:  {parent_after.hex()}")
        print(f"wait status:        {status}")
        print("If fork_aware=True, child should have reseeded on next bytes().")
        print("Inspect CHILD line above — should differ from parent after.")


def exp_state_compromise() -> None:
    banner("State-compromise / backtracking investigation")
    rng = TestRNG(b"compromise-demo")
    out_a = rng.bytes(32)
    snap = rng._experimental_state_snapshot()
    out_b = rng.bytes(32)
    out_c = rng.bytes(32)

    # Restore and try to reproduce B, C
    rng._experimental_restore_state(snap)
    repro_b = rng.bytes(32)
    repro_c = rng.bytes(32)
    print(f"A: {out_a.hex()}")
    print(f"B: {out_b.hex()}")
    print(f"C: {out_c.hex()}")
    print(f"Reproduce B from snapshot: {repro_b == out_b}")
    print(f"Reproduce C from snapshot: {repro_c == out_c}")

    # Can we reconstruct A from the post-A snapshot?
    # Snapshot was taken AFTER A and state evolution, so A should NOT
    # be recoverable by simply continuing generation.
    rng2 = TestRNG(b"compromise-demo")
    _ = rng2.bytes(32)  # produce A'
    snap_after_a = rng2._experimental_state_snapshot()
    # From snap_after_a we can get B', but not walk backward to A'.
    print("Backtracking: after Generate, HMAC-DRBG Update advances (Key, V);")
    print("prior output A is not exposed by continuing forward from the snapshot.")
    print(f"(snapshot Key length={len(snap_after_a['key'])} — not printed)")

    # Reseed changes the picture
    rng3 = TestRNG(b"compromise-demo")
    rng3.bytes(16)
    snap3 = rng3._experimental_state_snapshot()
    rng3.reseed(b"fresh-pool")
    after_reseed = rng3.bytes(32)
    rng3._experimental_restore_state(snap3)
    without_reseed = rng3.bytes(32)
    print(f"Reseed breaks reproduction: {after_reseed != without_reseed}")


def exp_all_failing_startup() -> None:
    banner("Startup failure (all sources down)")
    try:
        RNG(sources=[FailingEntropy(), FailingEntropy("x")])
        print("ERROR: should have failed")
    except InitializationError as exc:
        print(f"Loud failure (good): {exc}")


def main() -> int:
    print("PyEntropy adversarial experiments")
    print("Surviving these does NOT prove cryptographic security.\n")

    exp_all_predictable()
    exp_one_predictable()
    exp_one_zero()
    exp_one_unavailable()
    exp_timing_disabled()
    exp_filesystem_disabled()
    exp_cpu_load()
    exp_idle()
    exp_multiple_instances()
    exp_fork()
    exp_state_compromise()
    exp_all_failing_startup()

    print("\nAll adversarial experiments completed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
