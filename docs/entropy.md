# Entropy

Educational notes.  PyEntropy treats source output as **observations**,
not as certified entropy estimates.

## Entropy vs randomness

- **Entropy** (information-theoretic): uncertainty an attacker has about
  a value, given their knowledge and the process that produced it.
- **Statistical randomness**: absence of obvious patterns in samples
  (bit balance, byte frequencies, runs, …).

A sequence can look statistically random and still be fully predictable
to someone who knows the algorithm and seed.  Conversely, high-entropy
secrets can fail naive statistical tests if the sample is too small.

PyEntropy’s distribution experiments measure the second notion.  They
do **not** prove the first.

## Environmental observations

Sources under `pyentropy.entropy` return byte strings derived from:

- timing deltas of small workloads
- process / environment fingerprints
- filesystem metadata and op timing
- scheduler / load timing

Each result is wrapped as an `EntropySample` with source name and
timestamp.  Sources are **not** allowed to declare “I contain 32 bits of
entropy” as a trusted fact.  Any estimate in the lab scripts is
diagnostic only.

## Why timing is not automatically entropy

`time.perf_counter_ns()` deltas depend on:

- timer resolution and virtualisation
- CPU frequency scaling
- whether the workload is cache-warm
- how quiet or loaded the machine is
- measurement methodology itself

On a quiet VM with coarse timers, deltas may collide heavily.  On a busy
machine they may look noisier — still without a proof of unpredictability
to a local attacker.

The timing source therefore:

1. performs operations (arithmetic, memory, hashing, object creation, FS meta);
2. records **deltas**, not a single wall-clock read;
3. documents that low bits may be more informative than high bits — and
   that even low bits can be correlated.

## Accumulation and conditioning

Many weak observations are mixed into a fixed-size pool with a
cryptographic hash:

```
pool' = H(POOL-MIX || pool || sample || metadata)
```

Conditioning does **not** create entropy.  It compresses and mixes
whatever uncertainty was present.  If every input is known to an
attacker, the pool is known too.

## Failure modes worth studying

| Failure | What to watch |
|---------|----------------|
| Constant source | Pool still “mixes” but information is zero |
| Counter source | Fully predictable sequence |
| Empty / failing source | Must not insert `0x00…` placeholders |
| All sources fail at startup | Must raise, not limp into READY |
| Only process IDs | Diversification ≠ secret |

Use `experiments/adversarial_tests.py` and `experiments/entropy_analysis.py`
to probe these cases.
