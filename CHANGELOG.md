# Changelog

All notable changes to BoundSec are documented here.
Format based on [Keep a Changelog](https://keepachangelog.com/).

## [0.2.0] - 2026-09-06

Major research-focused rewrite. BoundSec moves from a static payload-replay
scanner to a **coverage-guided fuzzing framework** with a reproducible
ground-truth benchmark and a full empirical evaluation.

### Added
- **Behavioural coverage** (`core/coverage.py`): a black-box analogue of edge
  coverage for LLM agents over five dimensions (action, transition, guardrail,
  fault, novelty), folded into an AFL-style bitmap. Includes a dependency-free
  locality-sensitive SimHash for output novelty and a finite security-relevant
  argument abstraction.
- **Coverage-guided search** (`core/engine.py`, `core/corpus.py`,
  `core/scheduler.py`): power-scheduled seed corpus + discounted-UCB operator
  bandit driven by a blended coverage/compliance-gradient/bug reward.
- **18 semantic mutation operators** across 9 attack families, plus crossover
  (`core/operators.py`), replacing the 6 text transforms.
- **The Agent Gym** (`targets/gym.py`): deterministic instrumented agents with
  planted canaries, ground-truth labels, and 7 independently-toggleable defense
  layers across a naive->frontier robustness spectrum.
- **Live-model adapters** (`targets/live.py`): OpenAI/Groq-compatible and HTTP
  agent targets that activate automatically when an API key is present.
- **Detectors with continuous scores** (`core/oracle.py`): heuristic (weighted
  noisy-OR), canary (ground-truth-assisted), and ensemble, enabling ROC/PR.
- **Analysis suite** (`analysis/`): threshold-free detector metrics, bootstrap
  CIs, Mann-Whitney U, and Vargha-Delaney A12; a 4-experiment evaluation and 13
  publication figures + 2 methodology diagrams, all reproducible from a seed.
- CLI sub-commands: `fuzz`, `experiment`, `figures`, `benchmark`, `operators`,
  `seeds`.
- 61-test suite covering every module and the empirical claims.

### Changed
- CLI rewritten around targets/strategies/detectors.
- Report schema v2.0 (per-query rows with coverage and ground truth).

### Removed
- The single stateless HTTP harness and regex-only oracle (subsumed).
- The old intentionally-vulnerable FastAPI mock (superseded by the gym).
