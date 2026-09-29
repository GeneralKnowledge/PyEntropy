"""Tests for entropy sources and collector."""

from __future__ import annotations

import pytest

from pyentropy.entropy import (
    ConstantEntropy,
    CounterEntropy,
    EmptyEntropy,
    EntropyCollector,
    FailingEntropy,
    FilesystemEntropy,
    ProcessEntropy,
    RepeatingEntropy,
    SchedulerEntropy,
    TimingEntropy,
    TimestampEntropy,
)
from pyentropy.exceptions import EntropySourceError
from pyentropy.pool import EntropyPool


def test_timing_collects_nonzero() -> None:
    src = TimingEntropy(rounds=8)
    data = src.collect()
    assert isinstance(data, bytes)
    assert len(data) > 0


def test_process_collects() -> None:
    data = ProcessEntropy().collect()
    assert len(data) > 0


def test_filesystem_collects_or_raises_cleanly() -> None:
    src = FilesystemEntropy()
    data = src.collect()
    assert len(data) > 0


def test_filesystem_disabled() -> None:
    src = FilesystemEntropy(enabled=False)
    with pytest.raises(EntropySourceError):
        src.collect()


def test_scheduler_collects() -> None:
    data = SchedulerEntropy(bursts=4, spin=200).collect()
    assert len(data) > 0


def test_collector_records_failures() -> None:
    pool = EntropyPool()
    collector = EntropyCollector(
        sources=[ConstantEntropy(b"\x11" * 16), FailingEntropy(), EmptyEntropy()],
        pool=pool,
    )
    samples = collector.collect_once()
    assert len(samples) == 1
    diag = collector.diagnostics()
    assert diag["total_samples"] == 1
    assert diag["total_failures"] == 2
    assert diag["sources"]["failing"]["active"] is False
    assert diag["sources"]["constant"]["active"] is True


def test_collector_never_inserts_placeholder_for_failure() -> None:
    pool = EntropyPool()
    before = pool.snapshot()
    collector = EntropyCollector(sources=[FailingEntropy()], pool=pool)
    samples = collector.collect_once()
    assert samples == []
    # Pool unchanged because nothing was mixed.
    assert pool.snapshot() == before


def test_adversarial_sources() -> None:
    assert ConstantEntropy().collect() == b"\x00" * 64
    c = CounterEntropy()
    assert c.collect() != c.collect()
    assert len(TimestampEntropy().collect()) == 16
    assert len(RepeatingEntropy().collect()) == 64


def test_sample_wrapper() -> None:
    sample = TimingEntropy(rounds=4).sample()
    assert sample.source_name == "timing"
    assert len(sample.raw) > 0
    assert sample.timestamp > 0
