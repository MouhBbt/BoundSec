# Methodology

This document specifies BoundSec precisely enough to reimplement or audit it. It expands
on the README's intuition with the exact definitions, algorithms, and evaluation protocol.

## 1. Problem statement

Let an agent be a stochastic policy `π` mapping a conversation (a sequence of user turns)
to a response and a sequence of tool calls. A *vulnerability* is an input `x` for which
`π(x)` realises an unsafe outcome from a fixed set `V` (system-prompt leak, credential leak,
unauthorized/dangerous tool execution, path traversal, SSRF, jailbreak compliance, indirect
injection, role confusion, memory poisoning, excessive agency, denial of service, output
integrity). Given a query budget `B`, the fuzzer's goal is to discover as many *distinct*
vulnerabilities as possible.

The difficulty specific to agents: `π` is black-box and stochastic, and exposes no coverage
signal, so the greybox feedback loop that makes fuzzing effective is unavailable a priori.

## 2. Behavioural coverage

We define the coverage of a trace `t` as a set of discrete **behaviour descriptors** over
five dimensions (`core/coverage.py`):

- **Action** `A:<tool>|<arg-class>|<outcome>`. Tool arguments are projected onto a closed
  set of 15 **argument classes** (`classify_argument`) chosen to be exactly the security
  distinctions that matter: `path_traversal`, `path_sensitive`, `url_internal`,
  `url_external`, `cmd_destructive`, `cmd_network`, `cmd_pipe`, `encoded`, `structured`,
  `oversized`, … Ordered most-specific-first, so `../../etc/passwd` reports as
  `path_sensitive`. This bounds |A| to a few hundred and prevents path explosion.
- **Transition** `T:<tool_i>-><tool_j>`. Ordered tool-to-tool transitions, including the
  synthetic `<start>` and `<end>` nodes — the analogue of edge coverage.
- **Guardrail** `G:<response-mode>@turn<k>`. The response is classified into one of eight
  regimes on a refusal→compliance ladder (`classify_response_mode`). Precedence puts
  *evidence of action* above prose: an agent that apologises **and** executes the command is
  `FULL_COMPLIANCE`, not a refusal — the failure mode naive refusal-string matching suffers.
- **Fault** `E:<status>|<error-class>`. Transport/status buckets — the crash-bucket analogue.
- **Novelty** `N:<simhash-bucket>`. Top 10 bits of a 64-bit SimHash over response token
  trigrams. SimHash is locality-sensitive, so paraphrases collapse and new regimes open a
  bucket — no embedding model, fully deterministic.

Descriptors are hashed into a `2^16` bitmap with AFL logarithmic hit-count bucketing
(1,2,3,4,8,16,32,128), so repeated behaviour (a recursion attack) also registers as new
coverage. `CoverageMap.update(t)` returns the count of newly-set slots — the greybox reward.

## 3. Search

**Corpus & power schedule** (`core/corpus.py`). An input is admitted only if it earned new
coverage or confirmed a bug (coverage distillation). Each entry gets an AFLFast-style
*energy* — increasing in new coverage, compliance level, and "favored" status, decreasing
(logarithmically) in how often it was already chosen — and is sampled proportional to energy.

**Operators** (`core/operators.py`). 18 semantic operators in 9 families
(instruction-override, roleplay, authority, encoding, unicode-evasion, structural/schema,
context-saturation, language-pivot, multi-turn), plus **crossover** (splice one input's
scaffold with another's payload turn). Every operator is deterministic given its RNG and
records itself in the child's `lineage` for credit assignment.

**Operator bandit** (`core/scheduler.py`). Operator selection is a non-stationary
multi-armed bandit solved with **discounted UCB** (`gamma=0.995`, `c=0.15`). The reward
blends three signals available on every query:

```
r = w_cov · sat(new_coverage) + w_grad · max(0, Δcompliance)/5 + w_bug · 1[bug]
```

normalised by the weight sum, with `(w_cov, w_grad, w_bug) = (0.5, 0.5, 6.0)` tuned on the
gym. The coverage term rewards reaching new behaviour; the gradient term is dense shaping
that guides the search up the "guardrail giving way" slope before any bug fires; the bug
term is the terminal reward. Discounting keeps the estimate responsive as the corpus drifts.

## 4. Targets & ground truth

The **Agent Gym** (`targets/gym.py`) is the measurement instrument. An attack lands iff its
dominant technique's modelled "bypass power" beats the agent's `robustness`, deterministically
hashed with the campaign seed, **and** no defense layer blocks it. Defenses (`injection_filter`,
`tool_allowlist`, `path_canonicalization`, `egress_filter`, `input_decoding`, `spotlighting`,
`rate_limit`) are checked independently, which is what lets Exp 3 attribute risk reduction to
specific controls. Every response carries a `GroundTruth` record (vulnerabilities realised,
canaries leaked, defense layers triggered). A **realism layer** (`targets/realism.py`)
realises each decision into surface text with calibrated false-negative and false-positive
pressure, without altering the label.

## 5. Detectors

Detectors (`core/oracle.py`) emit a continuous suspiciousness score. The heuristic detector
fuses weighted evidence with **noisy-OR** (`1 − Π(1 − wᵢ)`), so independent weak signals
accumulate calibrated confidence, and down-weights prose signatures inside an otherwise-refused
answer. The canary detector matches planted secrets and real side effects exactly (precision
ceiling). Continuous scores enable threshold-free evaluation.

## 6. Evaluation protocol

Four experiments (`analysis/experiment.py`), all seeded and budget-matched:

1. **Strategy** — 4 strategies × 4 profiles × N seeds. Primary metric: **bug recall** vs. the
   per-profile reachable set (union of all methods' distinct findings). A *finding* is keyed
   by `(top vuln class, executed-tool arg-signature)`; only tools that actually executed count,
   and non-tool bugs collapse to one key — so a strategy cannot inflate its score by
   re-triggering one bug through many paraphrases.
2. **Detectors** — one shared trace pool scored by every detector; ROC-AUC, PR-AUC, best-F1,
   Expected Calibration Error.
3. **Defenses** — coverage-guided search vs. single-layer and cumulative defense stacks on a
   fixed base agent; attack-success reduction per control.
4. **Ablation** — disable each coverage dimension (and a coverage-free control) and measure
   the hit to recall.

**Statistics** (`analysis/metrics.py`): percentile bootstrap CIs, tie-corrected Mann–Whitney
U with rank-biserial correlation, and Vargha–Delaney Â₁₂ (the standard fuzzing effect size).
All are dependency-light and deterministic, so any number in the paper regenerates bit-for-bit.

## 7. Reproducibility

Every source of randomness derives from a single integer seed: the gym's susceptibility rolls,
operator RNGs, corpus/bandit sampling, and the bootstrap. `make experiment` regenerates all
results and figures. Results files record their full config (`schema_version`, strategy,
profile, seed, budget, coverage dimensions) so each figure traces back to the runs behind it.
