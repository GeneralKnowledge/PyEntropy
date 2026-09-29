# Security model

**PyEntropy is an educational implementation.**  This document states
assumptions and limits clearly so the project is not mistaken for a
production CSPRNG.

## Non-claims

Unless carefully qualified, this project does **not** claim to be:

- cryptographically secure
- equivalent to `/dev/urandom`
- safe for generating private keys
- production ready

## Assumptions (educational)

1. At least one entropy source returns some observation data at startup.
2. SHA-256 / SHA-512 behave as one-way, mixing functions for teaching
   purposes.
3. The process memory holding the secret is not readable by the attacker
   under study (except in explicit compromise experiments).
4. Domain-separated hashing prevents trivial cross-construction confusion.

None of these are a full real-world threat model.

## Attacker sketches

| Attacker | Question PyEntropy explores |
|----------|-----------------------------|
| Remote, sees only output | Do outputs look statistically unstructured? |
| Local, sees / controls some sources | Can predictable sources dominate? |
| Compromises current secret | Can past output be recovered? Future? |
| After fork without reseed | Do parent and child share a stream? |

## State compromise

An experimental-only snapshot API exists on the generator for labs:

1. Generate A  
2. Capture state  
3. Generate B, C  
4. Restore snapshot → check whether B/C reproduce  
5. Ask whether A can be reconstructed (backtracking)

State evolution aims to make retrospective recovery of **prior** output
non-trivial given only the **post-output** secret.  Reseeding aims to
limit damage for **future** output after compromise — once new
unpredictable pool material is mixed in.

These are investigation tools, not proofs.

## Reseeding

Default thresholds (1 MiB / 60 s) are **experimental knobs**.  They are
not guarantees against state compromise, VM snapshots, or weak sources.

## Why this is not an OS RNG replacement

OS CSPRNGs typically combine:

- privileged hardware / boot entropy
- long-studied designs and reviews
- kernel-enforced isolation
- continuous entropy accounting (with known debates)

PyEntropy runs in userspace Python, uses environmental jitter as a lab
input, and prioritises inspectability over assurance.  Use
`secrets` / `/dev/urandom` for real secret generation.

## Coding rules enforced by design

- No `random` / `secrets` / NumPy / OpenSSL RNG as the generator
- No wrapping `/dev/urandom` as the byte source
- No secret state in `status()` or CLI `--status`
- No silent predictable fallback on init failure
- No naive `x % n` for `randbelow`
- No logging of raw entropy samples in normal operation
