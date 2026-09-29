# Experiments

How to reproduce the PyEntropy laboratory work.  All scripts are
standalone and add `src/` to `sys.path` when needed.

```bash
# from repository root
python experiments/<script>.py
```

**Reminder:** surviving or “passing” experiments does not prove
cryptographic security.

## Entropy laboratory

```bash
python experiments/entropy_analysis.py
python experiments/entropy_analysis.py --source timing --samples 128
python experiments/timing_analysis.py --collections 64
```

Collects many observations per source and reports uniqueness, frequencies,
runs, and autocorrelation.  Useful for comparing idle vs loaded machines
manually (run once quietly, once under `stress` / extra Python threads).

## Distribution & correlation

```bash
python experiments/distribution_tests.py --bytes 100000
python experiments/correlation_tests.py --bytes 50000
```

Tests on **generator output** (not raw sources):

- bit balance, byte histogram / χ²
- bit runs, repeated blocks
- Hamming distance between blocks
- serial / lag correlation

These address statistical randomness only.

## Adversarial sources & scenarios

```bash
python experiments/adversarial_tests.py
```

Covers:

1. All sources predictable  
2. One source predictable  
3. One source constantly zero  
4. One source unavailable  
5. Timing omitted  
6. Filesystem disabled  
7. Heavy CPU load  
8. Idle-ish run  
9. Multiple RNG instances  
10. Fork behaviour (where `os.fork` exists)  
11. State-compromise / backtracking lab  
12. Loud startup failure when all sources die  

Adversarial source classes live in
`src/pyentropy/entropy/adversarial.py`
(`ConstantEntropy`, `CounterEntropy`, `TimestampEntropy`,
`RepeatingEntropy`, `FailingEntropy`, …).

## State compromise

The adversarial script includes a TestRNG-based walkthrough:

- reproduce forward output from a snapshot  
- observe that prior output is not obtained by continuing forward  
- show that reseeding breaks reproduction from a pre-reseed snapshot  

Application code should not call `_experimental_*` helpers.

## Benchmarks

```bash
python experiments/benchmark.py
```

Reports cost of output sizes and of collection / conditioning / reseed
steps.  Throughput is informational only.

## Unit tests

```bash
pip install -e ".[dev]"
pytest
```

## Suggested investigation loop

1. Run entropy analysis on each source.  
2. Disable or replace sources with adversarial ones.  
3. Watch whether `RNG()` still starts and what `status()` reports.  
4. Capture state and try to replay output.  
5. Fork and compare parent/child streams.  
6. Re-read [security-model.md](security-model.md) and challenge each
   assumption in code.
