"""End-to-end: strategies run, and guidance beats static replay."""
import asyncio
import statistics
import matplotlib
matplotlib.use("Agg")

from boundsec.core.engine import CampaignConfig, FuzzingEngine, build_strategy
from boundsec.core.oracle import HeuristicDetector
from boundsec.targets.gym import GymAgent
from boundsec.payloads.seeds import load_seeds


def _run(strategy, profile, seed, budget=200):
    cfg = CampaignConfig(budget=budget, seed=seed)
    eng = FuzzingEngine(GymAgent(profile, seed=seed), HeuristicDetector(),
                        build_strategy(strategy, load_seeds(), cfg), cfg)
    return asyncio.run(eng.run())


def test_all_strategies_run():
    for strat in ["static_replay", "random_mutation", "guided_no_bandit", "coverage_guided"]:
        res = _run(strat, "basic", 0, budget=120)
        assert res.queries_used > 0
        assert len(res.observations) == res.queries_used
        assert res.final_coverage > 0


def test_records_are_serializable(tmp_path):
    from boundsec.analysis.results import CampaignRecord, record_from_result
    res = _run("coverage_guided", "basic", 0, budget=120)
    rec = record_from_result(res, profile="basic", target="gym::basic")
    p = tmp_path / "rec.json"
    rec.to_json(p)
    loaded = CampaignRecord.from_json(p)
    assert loaded.n_unique_findings == res.n_findings
    assert len(loaded.rows) == len(res.observations)
    # exactly n_findings rows are marked as new findings
    assert sum(r["is_new_finding"] for r in loaded.rows) == res.n_findings


def test_coverage_guided_beats_static_replay():
    # Averaged over seeds, guided search finds strictly more on a hardened target.
    guided = [_run("coverage_guided", "hardened", s, budget=250).n_findings for s in range(5)]
    static = [_run("static_replay", "hardened", s, budget=250).n_findings for s in range(5)]
    assert statistics.mean(guided) > statistics.mean(static)


def test_guided_builds_a_corpus():
    res = _run("coverage_guided", "basic", 0, budget=200)
    assert res.corpus_size > len(load_seeds())  # it evolved new inputs
    assert res.scheduler_stats is not None


def test_no_coverage_control_underperforms():
    # dims=() -> inert coverage signal; should not beat real coverage guidance.
    cfg_full = CampaignConfig(budget=250, seed=0)
    cfg_none = CampaignConfig(budget=250, seed=0, dimensions=())
    full = asyncio.run(FuzzingEngine(GymAgent("hardened", seed=0), HeuristicDetector(),
                       build_strategy("coverage_guided", load_seeds(), cfg_full), cfg_full).run())
    none = asyncio.run(FuzzingEngine(GymAgent("hardened", seed=0), HeuristicDetector(),
                       build_strategy("coverage_guided", load_seeds(), cfg_none), cfg_none).run())
    assert full.final_coverage >= none.final_coverage
