# PyEntropy

**Educational / experimental userspace random-byte generator.**

PyEntropy implements a from-scratch Python RNG inspired by the *architecture*
behind Linux `/dev/urandom` (entropy sources → pool → conditioning →
generator state → output → reseed).  It is designed so you can inspect,
measure, experiment with, break, and improve every layer.

## What it is

- A teaching tool for entropy collection, conditioning, state evolution,
  reseeding, and statistical testing.
- A laboratory with adversarial sources, fork/thread experiments, and
  state-compromise investigations.
- Standard-library based (hashing via `hashlib`), with the RNG *architecture*
  implemented by this project.

## What it is not

- **Not** a replacement for `/dev/urandom`, `secrets`, or OS CSPRNGs.
- **Not** “cryptographically secure” in any certified sense.
- **Not** safe for generating private keys or production secrets.
- **Not** a wrapper around Python’s `random` / `secrets`, NumPy RNGs,
  OpenSSL RNGs, or `/dev/urandom`.

> Passing statistical tests does **not** establish cryptographic security.

## Architecture (overview)

```
entropy sources
      │
      ▼
entropy observations
      │
      ▼
entropy collector
      │
      ▼
entropy pool  (64 bytes, hash-mixed)
      │
      ▼
cryptographic conditioner  (domain-separated SHA-2)
      │
      ▼
generator state  (secret ≥ 256 bits + counters)
      │
      ▼
deterministic output generator  (hash DRBG-style)
      │
      ▼
random bytes  (+ state evolution, periodic reseed)
```

See [docs/architecture.md](docs/architecture.md) for the full pipeline.

## Installation

```bash
# From the repository root (editable)
pip install -e ".[dev]"

# Or just put src/ on PYTHONPATH
export PYTHONPATH=src
```

Requires **Python 3.12+**.  Runtime depends only on the standard library;
`pytest` is optional for development.

## Usage

```python
from pyentropy import RNG

rng = RNG()
print(rng.bytes(32))
print(rng.randbits(256))
print(rng.randbelow(1000))
print(rng.integer(-50, 50))
print(rng.hex(32))
print(rng.status())  # never includes secret state
rng.reseed()
```

### Deterministic test mode

```python
from pyentropy import TestRNG

t = TestRNG(b"fixed-seed")
assert t.bytes(32) == TestRNG(b"fixed-seed").bytes(32)
```

`TestRNG` is for tests/experiments only.  Normal `RNG()` **never** falls
back to deterministic output if entropy collection fails — it raises
`InitializationError`.

### CLI

```bash
python -m pyentropy 32
python -m pyentropy --hex 32
python -m pyentropy --base64 32
python -m pyentropy --integer 1 100
python -m pyentropy --status
```

## Experiments

```bash
python experiments/entropy_analysis.py
python experiments/timing_analysis.py
python experiments/distribution_tests.py
python experiments/correlation_tests.py
python experiments/adversarial_tests.py
python experiments/benchmark.py
```

Details: [docs/experiments.md](docs/experiments.md).

## Tests

```bash
pip install -e ".[dev]"
pytest
```

## Documentation

| Doc | Topic |
|-----|--------|
| [docs/architecture.md](docs/architecture.md) | Full pipeline |
| [docs/entropy.md](docs/entropy.md) | Observations vs entropy |
| [docs/security-model.md](docs/security-model.md) | Assumptions & limits |
| [docs/experiments.md](docs/experiments.md) | Reproducing labs |

## Security warning

This project exists to help you **understand why** bytes should or should
not be considered unpredictable.  Do not ship it as a production CSPRNG.
When choices are security-sensitive, they are documented — and often
intentionally left open to experimental challenge.

## License

MIT — see [LICENSE](LICENSE).
