"""Domain-separated encoding helpers for output formatting.

Educational RNG — not a production CSPRNG.
"""

from __future__ import annotations

import base64
import binascii


def to_hex(data: bytes) -> str:
    """Return lowercase hexadecimal encoding of *data*."""
    return binascii.hexlify(data).decode("ascii")


def to_base64(data: bytes) -> str:
    """Return standard Base64 encoding of *data* (no newlines)."""
    return base64.b64encode(data).decode("ascii")


def from_hex(text: str) -> bytes:
    """Decode a hexadecimal string to bytes."""
    return binascii.unhexlify(text.encode("ascii"))
