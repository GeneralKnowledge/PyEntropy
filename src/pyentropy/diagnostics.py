"""Diagnostics helpers that never leak secret state.

Educational RNG — not a production CSPRNG.
"""

from __future__ import annotations

import time
from typing import Any


def format_status(status: dict[str, Any]) -> str:
    """Render a human-readable status block for the CLI."""
    lines: list[str] = []
    lines.append(f"State: {status.get('state', 'UNKNOWN')}")
    lines.append(f"Pool size: {status.get('pool_size', '?')} bytes")
    lines.append(f"Reseed count: {status.get('reseed_count', 0)}")
    lines.append(f"Bytes generated: {status.get('bytes_generated', 0)}")
    lines.append(f"Generation count: {status.get('generation_count', 0)}")
    lines.append(f"Entropy samples: {status.get('entropy_samples', 0)}")
    lines.append(f"Source failures: {status.get('source_failures', 0)}")
    lines.append(f"Last reseed: {status.get('last_reseed_reason', 'n/a')}")
    uptime = status.get("uptime_seconds")
    if isinstance(uptime, (int, float)):
        lines.append(f"Uptime: {uptime:.3f}s")
    sources = status.get("sources")
    if isinstance(sources, dict):
        lines.append("Sources:")
        for name, info in sources.items():
            if isinstance(info, dict):
                active = info.get("active", False)
                label = "ACTIVE" if active else "INACTIVE"
                err = info.get("last_error") or ""
                extra = f" ({err})" if err and not active else ""
                lines.append(f"  {name:<12} {label}{extra}")
            else:
                lines.append(f"  {name:<12} {info}")
    # Explicitly never print anything named secret/state_bytes/pool_bytes.
    return "\n".join(lines)


def uptime_seconds(created_at: float) -> float:
    """Return seconds since *created_at* (monotonic)."""
    return max(0.0, time.monotonic() - created_at)
