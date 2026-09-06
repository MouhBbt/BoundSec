"""
BoundSec - Adaptive operator scheduler.

The fuzzer must repeatedly decide *which* mutation operator to apply next.  This
is an exploration/exploitation problem: early on we know nothing about which of
the 18 operators pay off against the current target, and their effectiveness is
target-dependent (an operator that defeats a regex filter is useless against a
strong aligned model).  We therefore treat operator selection as a
**non-stationary multi-armed bandit** and solve it with a discounted
Upper-Confidence-Bound rule (a variant of D-UCB, Garivier & Moulines 2011).

Reward design
-------------
The reward for applying an operator is *not* simply "did it find a bug".  Bugs
are sparse, so a bug-only reward gives almost no gradient.  Instead the reward
blends three signals available on every single query::

    r = w_cov * saturating(new_coverage)
      + w_grad * guardrail_gradient
      + w_bug * bug_indicator

* ``new_coverage`` is the number of new behavioural bitmap slots the child's
  trace lit up (from ``core/coverage.py``) - the greybox signal that rewards
  *reaching new agent behaviour* even when no vulnerability fires.
* ``guardrail_gradient`` rewards operators that push the agent's response mode
  toward compliance relative to its parent (see ``ResponseMode.compliance_level``)
  - a dense shaping term that guides the search up the "guardrail giving way"
  slope before any bug is found.
* ``bug_indicator`` is the terminal reward when the oracle confirms a finding.

Discounting (``gamma < 1``) makes the estimate forget stale evidence, which is
what keeps the scheduler responsive when an operator that used to work stops
working because the corpus has moved into a different region of behaviour space.
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass

from boundsec.core.operators import Operator, all_operators
from boundsec.core.types import ResponseMode


def saturating(x: float, k: float = 4.0) -> float:
    """Diminishing-returns squash into [0, 1): the 50th new slot matters less
    than the 1st, so raw slot counts are compressed before entering the reward."""
    return 1.0 - math.exp(-x / k)


@dataclass
class _Arm:
    name: str
    operator: Operator
    value: float = 0.0        # discounted mean reward estimate
    count: float = 0.0        # discounted pull count
    raw_pulls: int = 0
    raw_reward: float = 0.0
    bugs: int = 0
    new_cov_events: int = 0


@dataclass
class BanditConfig:
    """
    Defaults tuned on the gym (see ``experiments/exp_bandit_tuning``).  ``gamma``
    is kept just below 1: the gym is stationary, so heavy discounting only hurts
    exploitation, but a small amount of forgetting still helps when the corpus
    drifts into a new behavioural region during a long campaign.  ``c`` is small
    because operator value gaps are of order 0.1; a large exploration bonus (the
    original 0.6) swamps them and collapses the bandit to uniform sampling.
    """

    gamma: float = 0.995       # near-stationary: exploit the leading operator
    c: float = 0.15            # UCB exploration coefficient (value gaps ~0.1)
    w_cov: float = 0.5         # coverage reward (earned broadly -> weak op signal)
    w_grad: float = 0.5        # guardrail-compliance gradient (dense shaping)
    w_bug: float = 6.0         # terminal bug reward (the operator differentiator)
    warmup_pulls: int = 1      # force each arm to be tried this many times first


class OperatorScheduler:
    """
    Discounted-UCB bandit over the mutation operators.

    The scheduler is agnostic to whether the caller wants single- or
    multi-turn operators; ``choose(allow_multi_turn=False)`` masks the
    turn-adding arms, which the engine uses when the corpus entry it is
    mutating is already at the turn budget.
    """

    def __init__(
        self,
        operators: list[Operator] | None = None,
        config: BanditConfig | None = None,
        rng: random.Random | None = None,
    ) -> None:
        ops = operators if operators is not None else all_operators()
        self.cfg = config or BanditConfig()
        self.rng = rng or random.Random()
        self.arms: dict[str, _Arm] = {
            op.name: _Arm(name=op.name, operator=op) for op in ops
        }
        self._t = 0

    # ------------------------------------------------------------------
    # Selection
    # ------------------------------------------------------------------

    def choose(self, allow_multi_turn: bool = True) -> Operator:
        """Pick the next operator by discounted-UCB."""
        self._t += 1
        candidates = [
            a for a in self.arms.values()
            if allow_multi_turn or not a.operator.multi_turn
        ]

        # Warmup: guarantee minimum exploration of every arm.
        unpulled = [a for a in candidates if a.raw_pulls < self.cfg.warmup_pulls]
        if unpulled:
            return self.rng.choice(unpulled).operator

        total = sum(a.count for a in candidates) + 1e-9
        log_total = math.log(total + 1.0)

        best, best_score = None, -math.inf
        for a in candidates:
            n = a.count + 1e-9
            bonus = self.cfg.c * math.sqrt(log_total / n)
            score = a.value + bonus
            # Deterministic tie-break through the rng for reproducibility.
            score += self.rng.random() * 1e-9
            if score > best_score:
                best, best_score = a, score
        assert best is not None
        return best.operator

    # ------------------------------------------------------------------
    # Learning
    # ------------------------------------------------------------------

    def reward(
        self,
        op_name: str,
        *,
        new_coverage: int,
        parent_mode: ResponseMode | None,
        child_mode: ResponseMode | None,
        found_bug: bool,
    ) -> float:
        """Compute the blended reward and fold it into the arm estimate."""
        arm = self.arms.get(op_name)
        if arm is None:
            return 0.0

        cov_term = saturating(float(new_coverage))
        grad_term = 0.0
        if parent_mode is not None and child_mode is not None:
            delta = child_mode.compliance_level - parent_mode.compliance_level
            grad_term = max(0.0, delta) / 5.0
        bug_term = 1.0 if found_bug else 0.0

        r = (self.cfg.w_cov * cov_term
             + self.cfg.w_grad * grad_term
             + self.cfg.w_bug * bug_term)
        # Normalise into ~[0,1] by the max attainable weight sum.
        r /= (self.cfg.w_cov + self.cfg.w_grad + self.cfg.w_bug)

        g = self.cfg.gamma
        # Discounted incremental update (D-UCB bookkeeping).
        for other in self.arms.values():
            other.count *= g
            other.value = other.value  # value is a ratio, decayed via count below
        arm.count += 1.0
        # Exponentially-weighted mean of reward.
        alpha = 1.0 / arm.count if arm.count < 20 else (1.0 - g)
        arm.value += alpha * (r - arm.value)

        arm.raw_pulls += 1
        arm.raw_reward += r
        arm.bugs += int(found_bug)
        arm.new_cov_events += int(new_coverage > 0)
        return r

    # ------------------------------------------------------------------
    # Introspection / reporting
    # ------------------------------------------------------------------

    def stats(self) -> list[dict[str, float | str]]:
        rows: list[dict[str, float | str]] = []
        for a in sorted(self.arms.values(), key=lambda x: -x.value):
            rows.append({
                "operator": a.name,
                "family": a.operator.family.value,
                "value": round(a.value, 4),
                "pulls": a.raw_pulls,
                "mean_reward": round(a.raw_reward / a.raw_pulls, 4) if a.raw_pulls else 0.0,
                "bugs": a.bugs,
                "cov_events": a.new_cov_events,
            })
        return rows

    def family_credit(self) -> dict[str, float]:
        """Total bugs found per attack-technique family - the credit assignment
        that the operator-effectiveness figure in the evaluation visualises."""
        out: dict[str, float] = {}
        for a in self.arms.values():
            fam = a.operator.family.value
            out[fam] = out.get(fam, 0.0) + a.bugs
        return out
