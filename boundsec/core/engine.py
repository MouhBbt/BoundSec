"""
BoundSec - Fuzzing engine and search strategies.

This module contains the campaign loop and the four search strategies the
evaluation compares.  All four share the *same* target, oracle, seed set and
query budget; they differ only in how they choose the next input.  Holding
everything else fixed is what makes the comparison a clean ablation of the
search strategy itself.

Strategies
----------
``StaticReplay``
    Replays the curated payload corpus once (the behaviour of the original
    BoundSec and of most published "jailbreak benchmark" harnesses).  No
    feedback.  This is the baseline a guided fuzzer must beat.

``RandomMutation``
    Blackbox mutation: pick a random seed, apply a random operator, discard all
    feedback.  Isolates the value of *feedback* from the value of *mutation*.

``CoverageGuided``
    The full method: coverage-distilled corpus + power schedule (``corpus.py``)
    + discounted-UCB operator bandit (``scheduler.py``), driven by the
    behavioural-coverage reward (``coverage.py``).

``GuidedNoBandit``
    Ablation: coverage guidance with the operator bandit replaced by uniform
    operator choice.  Isolates the contribution of adaptive operator selection.

Every strategy yields a stream of :class:`Observation` rows, so the analysis
layer treats them identically.
"""

from __future__ import annotations

import random
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from boundsec.core.corpus import Corpus
from boundsec.core.coverage import CoverageMap, classify_response_mode
from boundsec.core.operators import all_operators, crossover
from boundsec.core.oracle import BaseDetector
from boundsec.core.scheduler import BanditConfig, OperatorScheduler
from boundsec.core.types import (
    FuzzCase,
    Observation,
    ResponseMode,
    ToolOutcome,
)
from boundsec.targets.base import Target


@dataclass
class CampaignConfig:
    budget: int = 500                 # total target queries
    seed: int = 0
    max_turns: int = 4                # cap on multi-turn escalation depth
    crossover_prob: float = 0.15
    bandit: BanditConfig = field(default_factory=BanditConfig)
    dimensions: tuple[str, ...] | None = None   # coverage dims (None = all)
    label: str = "campaign"


@dataclass
class CampaignResult:
    strategy: str
    label: str
    observations: list[Observation]
    coverage_history: list[int]
    unique_findings: dict[str, Observation]      # dedup key -> first finding
    scheduler_stats: list[dict] | None
    corpus_size: int
    queries_used: int
    wall_time_s: float
    config: CampaignConfig

    @property
    def n_findings(self) -> int:
        return len(self.unique_findings)

    @property
    def final_coverage(self) -> int:
        return self.coverage_history[-1] if self.coverage_history else 0


# ---------------------------------------------------------------------------
# Strategy base
# ---------------------------------------------------------------------------


class SearchStrategy(ABC):
    """A policy for producing the next :class:`FuzzCase` to execute."""

    name: str = "abstract"

    def __init__(self, seeds: list[FuzzCase], cfg: CampaignConfig) -> None:
        self.seeds = seeds
        self.cfg = cfg
        self.rng = random.Random(cfg.seed)

    @abstractmethod
    def next_case(self) -> FuzzCase | None:
        """Return the next case, or None when the strategy is exhausted."""

    def observe(self, obs: Observation) -> None:
        """Feedback hook. No-op for feedback-free strategies."""


class StaticReplay(SearchStrategy):
    name = "static_replay"

    def __init__(self, seeds, cfg):
        super().__init__(seeds, cfg)
        self._queue = list(seeds)
        self._i = 0

    def next_case(self):
        # Loop the corpus if budget exceeds its size, so the query budget is
        # spent fairly against the other strategies.
        if not self._queue:
            return None
        case = self._queue[self._i % len(self._queue)]
        self._i += 1
        return case


class RandomMutation(SearchStrategy):
    name = "random_mutation"

    def __init__(self, seeds, cfg):
        super().__init__(seeds, cfg)
        self._ops = all_operators()
        self._pool = list(seeds)

    def next_case(self):
        parent = self.rng.choice(self._pool)
        op = self.rng.choice(self._ops)
        allow = parent.n_turns < self.cfg.max_turns
        if op.multi_turn and not allow:
            op = self.rng.choice([o for o in self._ops if not o.multi_turn])
        child = op.apply(parent, self.rng)
        return child or parent


class CoverageGuided(SearchStrategy):
    """The full coverage-guided evolutionary strategy."""

    name = "coverage_guided"

    def __init__(self, seeds, cfg, use_bandit: bool = True):
        super().__init__(seeds, cfg)
        # The instance name reflects the ablation variant so results are labelled
        # distinctly (the class attribute alone cannot tell the two apart).
        self.name = "coverage_guided" if use_bandit else "guided_no_bandit"
        self.corpus = Corpus(rng=self.rng)
        for s in seeds:
            self.corpus.add_seed(s)
        self.use_bandit = use_bandit
        self.scheduler = OperatorScheduler(
            config=cfg.bandit, rng=self.rng
        ) if use_bandit else None
        self._ops = all_operators()
        self._pending: tuple[str, ResponseMode] | None = None
        self._last_parent_mode = ResponseMode.HARD_REFUSAL

    def next_case(self):
        entry = self.corpus.select()
        parent = entry.case
        self._last_parent_mode = ResponseMode(
            parent.metadata.get("response_mode", ResponseMode.HARD_REFUSAL.value)
        )
        allow_mt = parent.n_turns < self.cfg.max_turns

        # Occasionally recombine with another corpus entry.
        if len(self.corpus) > 2 and self.rng.random() < self.cfg.crossover_prob:
            other = self.corpus.select().case
            child = crossover(parent, other, self.rng)
            self._pending = ("_crossover", self._last_parent_mode)
            if child.n_turns > self.cfg.max_turns:
                child.turns = child.turns[-self.cfg.max_turns:]
            return child

        if self.use_bandit and self.scheduler is not None:
            op = self.scheduler.choose(allow_multi_turn=allow_mt)
        else:
            pool = self._ops if allow_mt else [o for o in self._ops if not o.multi_turn]
            op = self.rng.choice(pool)

        child = op.apply(parent, self.rng)
        if child is None:
            child = parent
        self._pending = (op.name, self._last_parent_mode)
        return child

    def observe(self, obs):
        self.corpus.consider(obs)
        if self._pending and self.scheduler is not None:
            op_name, parent_mode = self._pending
            if op_name != "_crossover":
                self.scheduler.reward(
                    op_name,
                    new_coverage=obs.new_coverage,
                    parent_mode=parent_mode,
                    child_mode=obs.response_mode,
                    found_bug=obs.verdict.is_vulnerable,
                )
        self._pending = None


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------

STRATEGIES: dict[str, type[SearchStrategy]] = {
    "static_replay": StaticReplay,
    "random_mutation": RandomMutation,
    "coverage_guided": CoverageGuided,
}


def _finding_key(obs: Observation) -> str:
    """
    Deduplicate findings the way a triage engineer would: two findings are
    "the same bug" if they share the same top vulnerability class *and* the
    same *realised* action signature.  Two subtleties keep the count honest:

    * Only tools that actually **executed** (outcome OK) enter the signature -
      a tool the agent tried but that a defense *blocked* is not part of the
      vulnerability and must not create spurious distinct findings.
    * Non-tool vulnerabilities (a DoS from oversized context, a prose leak)
      have no action signature, so every realisation of that one mechanism
      collapses to a single key - a strategy cannot inflate its score by
      re-triggering the same resource-exhaustion bug through different payloads.

    Unique bugs, not raw hits, are what the evaluation counts.
    """
    vclass = obs.verdict.top_class.value if obs.verdict.top_class else "generic"
    executed = [tc for tc in obs.trace.tool_calls if tc.outcome == ToolOutcome.OK]
    tool_sig = "|".join(sorted({
        f"{tc.tool_name}:{_arg_bucket(tc.arguments)}" for tc in executed
    })) or "no_tool"
    return f"{vclass}#{tool_sig}"


def _arg_bucket(args: dict) -> str:
    from boundsec.core.coverage import classify_argument
    return "+".join(sorted({classify_argument(v) for v in args.values()})) or "noargs"


class FuzzingEngine:
    """
    Runs one strategy against one target under a fixed query budget.

    The engine is synchronous at the step level (each query depends on the
    feedback from the previous one for guided strategies) but delegates the
    actual I/O to the target's async ``query`` through a small run loop.
    """

    def __init__(
        self,
        target: Target,
        detector: BaseDetector,
        strategy: SearchStrategy,
        cfg: CampaignConfig,
    ) -> None:
        self.target = target
        self.detector = detector
        self.strategy = strategy
        self.cfg = cfg
        self.coverage = CoverageMap(dimensions=cfg.dimensions)

    async def run(self, progress_cb=None) -> CampaignResult:
        observations: list[Observation] = []
        findings: dict[str, Observation] = {}
        start = time.monotonic()
        step = 0

        while step < self.cfg.budget:
            case = self.strategy.next_case()
            if case is None:
                break

            trace = await self.target.query(case)
            trace.case_id = case.case_id
            # Ensure response_mode is materialised for downstream consumers.
            mode = classify_response_mode(trace)
            trace.metadata["response_mode"] = mode.value
            case.metadata["response_mode"] = mode.value

            new_cov = self.coverage.update(trace)
            verdict = self.detector.evaluate(case, trace)

            obs = Observation(
                case=case,
                trace=trace,
                verdict=verdict,
                new_coverage=new_cov,
                total_coverage=self.coverage.size,
                step=step,
                wall_time_s=time.monotonic() - start,
                queries_used=trace.n_turns or 1,
            )
            observations.append(obs)
            self.strategy.observe(obs)

            if verdict.is_vulnerable:
                key = _finding_key(obs)
                if key not in findings:
                    findings[key] = obs

            step += 1
            if progress_cb and step % 10 == 0:
                progress_cb(step, self.cfg.budget, self.coverage.size, len(findings))

        wall = time.monotonic() - start
        sched_stats = None
        corpus_size = 0
        if isinstance(self.strategy, CoverageGuided):
            corpus_size = len(self.strategy.corpus)
            if self.strategy.scheduler is not None:
                sched_stats = self.strategy.scheduler.stats()

        return CampaignResult(
            strategy=self.strategy.name,
            label=self.cfg.label,
            observations=observations,
            coverage_history=self.coverage.history,
            unique_findings=findings,
            scheduler_stats=sched_stats,
            corpus_size=corpus_size,
            queries_used=step,
            wall_time_s=wall,
            config=self.cfg,
        )


def build_strategy(name: str, seeds: list[FuzzCase], cfg: CampaignConfig) -> SearchStrategy:
    if name == "guided_no_bandit":
        return CoverageGuided(seeds, cfg, use_bandit=False)
    if name not in STRATEGIES:
        raise ValueError(f"Unknown strategy '{name}'. Choices: {list(STRATEGIES)} + guided_no_bandit")
    return STRATEGIES[name](seeds, cfg)
