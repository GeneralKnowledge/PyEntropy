"""Composite entropy collector.

Educational RNG — not a production CSPRNG.

Invokes configured sources, records successes and failures, and never
silently replaces missing entropy with a predictable value.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from pyentropy.entropy.base import EntropySample, EntropySource
from pyentropy.entropy.filesystem import FilesystemEntropy
from pyentropy.entropy.process import ProcessEntropy
from pyentropy.entropy.scheduler import SchedulerEntropy
from pyentropy.entropy.timing import TimingEntropy
from pyentropy.pool import EntropyPool


@dataclass
class SourceRecord:
    """Per-source collection diagnostics (non-secret)."""

    name: str
    success_count: int = 0
    failure_count: int = 0
    last_error: str = ""
    last_success_at: float = 0.0
    last_failure_at: float = 0.0
    bytes_collected: int = 0
    active: bool = True


@dataclass
class CollectorDiagnostics:
    """Aggregate collector diagnostics."""

    total_samples: int = 0
    total_failures: int = 0
    sources: dict[str, SourceRecord] = field(default_factory=dict)


class EntropyCollector:
    """Invoke multiple entropy sources and mix observations into a pool."""

    def __init__(
        self,
        sources: list[EntropySource] | None = None,
        *,
        pool: EntropyPool | None = None,
    ) -> None:
        self._sources: list[EntropySource] = list(
            sources if sources is not None else default_sources()
        )
        self._pool = pool if pool is not None else EntropyPool()
        self._diag = CollectorDiagnostics()
        for src in self._sources:
            self._diag.sources[src.name] = SourceRecord(name=src.name)

    @property
    def pool(self) -> EntropyPool:
        return self._pool

    @property
    def sources(self) -> list[EntropySource]:
        return list(self._sources)

    def collect_once(self) -> list[EntropySample]:
        """Invoke every source once; mix successful samples into the pool.

        Failed sources are recorded.  No predictable placeholder is inserted
        for a failed source.
        """
        samples: list[EntropySample] = []
        for src in self._sources:
            record = self._diag.sources.setdefault(src.name, SourceRecord(name=src.name))
            try:
                sample = src.sample()
            except Exception as exc:  # noqa: BLE001 — record any source failure
                record.failure_count += 1
                record.last_error = f"{type(exc).__name__}: {exc}"
                record.last_failure_at = time.monotonic()
                record.active = False
                self._diag.total_failures += 1
                continue

            if not sample.raw:
                record.failure_count += 1
                record.last_error = "empty observation"
                record.last_failure_at = time.monotonic()
                record.active = False
                self._diag.total_failures += 1
                continue

            self._pool.mix(sample.raw, source_name=sample.source_name)
            record.success_count += 1
            record.bytes_collected += len(sample.raw)
            record.last_success_at = sample.timestamp
            record.last_error = ""
            record.active = True
            self._diag.total_samples += 1
            samples.append(sample)
        return samples

    def collect_until(self, *, min_successes: int = 1, max_rounds: int = 8) -> int:
        """Collect rounds until *min_successes* samples or *max_rounds*."""
        if min_successes < 1:
            raise ValueError("min_successes must be >= 1")
        total = 0
        for _ in range(max_rounds):
            got = self.collect_once()
            total += len(got)
            if total >= min_successes:
                break
        return total

    def diagnostics(self) -> dict[str, object]:
        """Return non-secret collector diagnostics."""
        sources_out: dict[str, dict[str, object]] = {}
        for name, rec in self._diag.sources.items():
            sources_out[name] = {
                "active": rec.active,
                "success_count": rec.success_count,
                "failure_count": rec.failure_count,
                "bytes_collected": rec.bytes_collected,
                "last_error": rec.last_error,
            }
        return {
            "total_samples": self._diag.total_samples,
            "total_failures": self._diag.total_failures,
            "sources": sources_out,
            "pool": self._pool.diagnostics(),
        }


def default_sources() -> list[EntropySource]:
    """Return the default experimental entropy source set."""
    return [
        TimingEntropy(),
        ProcessEntropy(),
        FilesystemEntropy(),
        SchedulerEntropy(),
    ]
