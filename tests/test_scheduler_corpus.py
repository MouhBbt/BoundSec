"""Bandit scheduler and corpus power schedule."""
import random
from boundsec.core.scheduler import BanditConfig, OperatorScheduler
from boundsec.core.corpus import Corpus
from boundsec.core.types import (
    AgentTrace, FuzzCase, Observation, ResponseMode, Verdict)


def test_bandit_learns_effective_operator():
    rng = random.Random(0)
    sch = OperatorScheduler(rng=rng, config=BanditConfig())
    good = "base64_wrap"
    for _ in range(500):
        op = sch.choose()
        if op.name == good:
            sch.reward(op.name, new_coverage=5,
                       parent_mode=ResponseMode.HARD_REFUSAL,
                       child_mode=ResponseMode.FULL_COMPLIANCE, found_bug=True)
        else:
            sch.reward(op.name, new_coverage=0,
                       parent_mode=ResponseMode.HARD_REFUSAL,
                       child_mode=ResponseMode.HARD_REFUSAL, found_bug=False)
    stats = sch.stats()
    assert stats[0]["operator"] == good
    # the good arm should be pulled clearly more than the median arm
    pulls = sorted(r["pulls"] for r in stats)
    good_pulls = next(r["pulls"] for r in stats if r["operator"] == good)
    assert good_pulls > pulls[len(pulls) // 2]


def test_corpus_admits_only_interesting():
    c = Corpus(random.Random(0))
    c.add_seed(FuzzCase(turns=["seed"]))
    boring = Observation(case=FuzzCase(turns=["b"]), trace=AgentTrace(),
                         verdict=Verdict(case_id="b"), new_coverage=0)
    assert c.consider(boring) is None
    interesting = Observation(case=FuzzCase(turns=["i"], generation=1),
                              trace=AgentTrace(metadata={"response_mode": "partial_compliance"}),
                              verdict=Verdict(case_id="i"), new_coverage=3)
    assert c.consider(interesting) is not None
    assert len(c) == 2


def test_corpus_power_schedule_prefers_high_energy():
    c = Corpus(random.Random(0))
    c.add_seed(FuzzCase(turns=["low"]))
    hot = Observation(case=FuzzCase(turns=["hot"], generation=1),
                      trace=AgentTrace(metadata={"response_mode": "full_compliance"}),
                      verdict=Verdict(case_id="h", is_vulnerable=True), new_coverage=8)
    c.consider(hot)
    picks = [c.select().case.turns[0] for _ in range(300)]
    assert picks.count("hot") > picks.count("low")
