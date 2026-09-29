"""PyEntropy exception hierarchy.

Educational RNG — not a production CSPRNG.
"""

from __future__ import annotations


class PyEntropyError(Exception):
    """Base exception for all PyEntropy errors."""


class InitializationError(PyEntropyError):
    """Raised when RNG startup cannot collect usable entropy."""


class EntropySourceError(PyEntropyError):
    """Raised when an entropy source fails during collection."""


class ValidationError(PyEntropyError, ValueError):
    """Raised when API arguments are invalid."""


class NotReadyError(PyEntropyError):
    """Raised when the generator is used before it is READY."""
