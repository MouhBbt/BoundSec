# Contributing to BoundSec

Contributions are welcome — new mutation operators, coverage dimensions, detectors, gym
defense layers, or live-target adapters are all high-value.

## Setup

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,live]"
make test            # 61 tests, must stay green
```

## Where things live

- A new **attack** → add an `@operator(...)` in `boundsec/core/operators.py` (and a seed in
  `boundsec/payloads/seeds.py` if it needs a new root intent).
- A new **coverage signal** → extend `extract_descriptors` in `boundsec/core/coverage.py`
  and add it to `DIMENSIONS`; Exp 4 will ablate it automatically.
- A new **detector** → subclass `BaseDetector` in `boundsec/core/oracle.py`.
- A new **defense** or agent behaviour → `boundsec/targets/gym.py` (keep it deterministic
  and add a ground-truth assertion in `tests/test_gym.py`).

## Ground rules

- **Determinism.** Everything must be reproducible from a seed. No wall-clock or unseeded RNG
  in the search or the gym.
- **Tests.** Add a test for every new behaviour; empirical claims get an integration test
  (see `tests/test_engine_integration.py`).
- **Style.** `ruff check boundsec tests` clean; match the surrounding docstring density.
- **Honesty.** If a change alters a headline number, regenerate `results/` and the figures in
  the same PR and update the README numbers.
