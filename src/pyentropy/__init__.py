"""PyEntropy — educational from-scratch userspace RNG.

This package explores entropy collection, conditioning, state evolution,
and reseeding.  It is NOT a cryptographically certified CSPRNG and is
NOT a replacement for /dev/urandom, the secrets module, or OS generators.
"""

from pyentropy.exceptions import (
    EntropySourceError,
    InitializationError,
    NotReadyError,
    PyEntropyError,
    ValidationError,
)
from pyentropy.rng import RNG, TestRNG

__all__ = [
    "RNG",
    "TestRNG",
    "PyEntropyError",
    "InitializationError",
    "EntropySourceError",
    "ValidationError",
    "NotReadyError",
]

__version__ = "0.1.0"
