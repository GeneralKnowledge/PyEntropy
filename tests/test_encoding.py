"""Tests for encoding helpers."""

from __future__ import annotations

from pyentropy.encoding import from_hex, to_base64, to_hex


def test_hex_roundtrip() -> None:
    data = bytes(range(256))
    assert from_hex(to_hex(data)) == data


def test_hex_lowercase() -> None:
    assert to_hex(b"\xab\xcd") == "abcd"


def test_base64() -> None:
    assert to_base64(b"hello") == "aGVsbG8="
