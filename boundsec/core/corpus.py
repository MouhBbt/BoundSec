"""
BoundSec - Seed corpus with coverage-guided power scheduling.

The corpus holds the inputs the fuzzer considers worth mutating.  Following
greybox practice, an input is admitted **only if it contributed new coverage**;
this keeps the corpus small and every entry behaviourally distinct.

Which corpus entry to mutate next is decided by a *power schedule* (AFLFast,
Bohme et al. 2016).  Each entry is assigned an *energy* proportional to how
promising it looks and inversely proportional to how often it has already been
chosen, so the search naturally concentrates on::

  * inputs that recently produced new coverage (they sit near an unexplored
    frontier), and
  * inputs that drove the agent toward compliance (high ``reward``) but have
    not yet been fully exploited,

while still occasionally revisiting stale entries.  Energy is turned into a
selection probability, giving a stochastic but strongly guided schedule.  This
is the seed-level counterpart to the operator-level bandit in
``core/scheduler.py``: one chooses *what* to mutate, the other *how*.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass

from boundsec.core.types import FuzzCase, Observation


@dataclass
class CorpusEntry:
    case: FuzzCase
    #: Coverage slots this input was first responsible for.
    new_coverage: int = 0
    #: Blended attractiveness in [0, 1] (compliance gradient + bug proximity).
    reward: float = 0.0
    times_chosen: int = 0
    depth: int = 0                      # generations from a root seed
    found_bug: bool = False
    response_level: int = 0             # compliance_level of its trace
    favored: bool = False               # minimal-set favourite (AFL "favored")

    def energy(self, total_chosen: int) -> float:
        """
        AFLFast-style energy.  High when the entry is fresh, reached deep new
        behaviour, or nearly complied; damped the more it has been chosen.
        """
        base = 1.0 + self.new_coverage
        promise = 1.0 + 3.0 * self.reward + 0.4 * self.response_level
        favor = 2.5 if self.favored else 1.0
        # Logarithmic fatigue: revisit, but with diminishing frequency.
        fatigue = 1.0 / (1.0 + math.log2(1 + self.times_chosen))
        # Mild global annealing keeps early entries from starving late ones.
        anneal = 1.0 + 0.05 * math.log1p(total_chosen)
        return base * promise * favor * fatigue / anneal


class Corpus:
    """Coverage-distilled seed pool with a stochastic power schedule."""

    def __init__(self, rng: random.Random | None = None) -> None:
        self.entries: list[CorpusEntry] = []
        self.rng = rng or random.Random()
        self._by_hash: dict[str, CorpusEntry] = {}
        self._total_chosen = 0

    # ------------------------------------------------------------------
    # Population
    # ------------------------------------------------------------------

    def add_seed(self, case: FuzzCase) -> CorpusEntry:
        entry = CorpusEntry(case=case, new_coverage=1, reward=0.1, depth=0, favored=True)
        self.entries.append(entry)
        self._by_hash[case.content_hash()] = entry
        return entry

    def consider(self, obs: Observation) -> CorpusEntry | None:
        """
        Admit ``obs``'s input into the corpus iff it earned new coverage or
        confirmed a bug.  Returns the new entry, or ``None`` if rejected.
        """
        interesting = obs.new_coverage > 0 or obs.verdict.is_vulnerable
        if not interesting:
            return None

        h = obs.case.content_hash()
        if h in self._by_hash:            # already have this exact input
            existing = self._by_hash[h]
            existing.new_coverage = max(existing.new_coverage, obs.new_coverage)
            return None

        level = obs.response_mode.compliance_level
        reward = _entry_reward(obs)
        entry = CorpusEntry(
            case=obs.case,
            new_coverage=obs.new_coverage,
            reward=reward,
            depth=obs.case.generation,
            found_bug=obs.verdict.is_vulnerable,
            response_level=level,
            favored=obs.new_coverage >= 2 or obs.verdict.is_vulnerable,
        )
        self.entries.append(entry)
        self._by_hash[h] = entry
        return entry

    # ------------------------------------------------------------------
    # Scheduling
    # ------------------------------------------------------------------

    def select(self) -> CorpusEntry:
        """Sample an entry proportional to its power-schedule energy."""
        if not self.entries:
            raise RuntimeError("Corpus is empty - add seeds before selecting.")
        weights = [e.energy(self._total_chosen) for e in self.entries]
        total = sum(weights)
        if total <= 0:
            entry = self.rng.choice(self.entries)
        else:
            r = self.rng.random() * total
            upto = 0.0
            entry = self.entries[-1]
            for e, w in zip(self.entries, weights, strict=False):
                upto += w
                if upto >= r:
                    entry = e
                    break
        entry.times_chosen += 1
        self._total_chosen += 1
        return entry

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    def __len__(self) -> int:
        return len(self.entries)

    @property
    def n_bug_entries(self) -> int:
        return sum(1 for e in self.entries if e.found_bug)

    def depth_histogram(self) -> dict[int, int]:
        hist: dict[int, int] = {}
        for e in self.entries:
            hist[e.depth] = hist.get(e.depth, 0) + 1
        return hist

    def frontier(self, n: int = 10) -> list[CorpusEntry]:
        """The highest-energy entries - the current search frontier."""
        return sorted(
            self.entries, key=lambda e: e.energy(self._total_chosen), reverse=True
        )[:n]


def _entry_reward(obs: Observation) -> float:
    """Attractiveness of keeping this input around for future mutation."""
    level = obs.response_mode.compliance_level / 5.0
    cov = 1.0 - math.exp(-obs.new_coverage / 4.0)
    bug = 1.0 if obs.verdict.is_vulnerable else 0.0
    return min(1.0, 0.5 * level + 0.3 * cov + 0.2 * bug)
