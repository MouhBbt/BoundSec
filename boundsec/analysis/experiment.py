"""
BoundSec - Experiment orchestration.

Runs the controlled comparisons that constitute the evaluation and writes one
:class:`CampaignRecord` per (experiment, strategy, profile, seed) cell.  The
experiments are:

* ``exp1_strategy`` - the headline: four search strategies x four agent
  profiles x N seeds, fixed query budget.  Establishes that coverage-guided
  search finds more unique vulnerabilities than static replay / blind mutation.
* ``exp2_detectors`` - detector quality: replay a shared pool of traces through
  every detector and score ROC/PR/calibration against gym ground truth.
* ``exp3_defenses`` - defense effectiveness: sweep single-layer and cumulative
  defense configurations, measuring attack-success reduction per control.
* ``exp4_ablation`` - coverage-dimension ablation: guide the search with a subset
  of behavioural coverage dimensions while scoring how much of the FULL behaviour
  space it explores, isolating each dimension's (non-circular) contribution.

All four share seeds and budget so their numbers are mutually comparable, and
every cell is reproducible from its recorded (seed, config).
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field
from pathlib import Path

from boundsec.analysis.results import CampaignRecord, record_from_result
from boundsec.core.coverage import DIMENSIONS
from boundsec.core.engine import CampaignConfig, FuzzingEngine, build_strategy
from boundsec.core.oracle import CanaryDetector, EnsembleDetector, HeuristicDetector
from boundsec.payloads.seeds import load_seeds
from boundsec.targets.gym import DefenseConfig, GymAgent

STRATEGIES = ["static_replay", "random_mutation", "guided_no_bandit", "coverage_guided"]
PROFILES = ["naive", "basic", "hardened", "frontier"]


@dataclass
class ExperimentConfig:
    budget: int = 600
    n_seeds: int = 10
    out_dir: Path = Path("results")
    profiles: list[str] = field(default_factory=lambda: list(PROFILES))
    strategies: list[str] = field(default_factory=lambda: list(STRATEGIES))
    verbose: bool = True


def _log(cfg: ExperimentConfig, msg: str) -> None:
    if cfg.verbose:
        print(msg, flush=True)


async def _campaign(strategy: str, profile: str, seed: int, budget: int,
                    dimensions=None) -> CampaignRecord:
    seeds = load_seeds()
    target = GymAgent(profile, seed=seed)
    ccfg = CampaignConfig(budget=budget, seed=seed, dimensions=dimensions,
                          label=f"{strategy}/{profile}/s{seed}")
    engine = FuzzingEngine(target, HeuristicDetector(),
                           build_strategy(strategy, seeds, ccfg), ccfg)
    result = await engine.run()
    return record_from_result(result, profile=profile, target=target.name)


# ---------------------------------------------------------------------------
# Experiment 1 - strategy comparison
# ---------------------------------------------------------------------------


async def exp1_strategy(cfg: ExperimentConfig) -> None:
    out = cfg.out_dir / "exp1_strategy"
    _log(cfg, f"[exp1] strategy comparison -> {out}")
    t0 = time.monotonic()
    total = len(cfg.strategies) * len(cfg.profiles) * cfg.n_seeds
    done = 0
    for profile in cfg.profiles:
        for strategy in cfg.strategies:
            for seed in range(cfg.n_seeds):
                rec = await _campaign(strategy, profile, seed, cfg.budget)
                rec.to_json(out / f"{strategy}__{profile}__s{seed:02d}.json")
                done += 1
            _log(cfg, f"[exp1]   {profile}/{strategy}: {cfg.n_seeds} seeds "
                      f"({done}/{total})")
    _log(cfg, f"[exp1] done in {time.monotonic()-t0:.1f}s")


# ---------------------------------------------------------------------------
# Experiment 2 - detector quality (shared trace pool)
# ---------------------------------------------------------------------------


async def exp2_detectors(cfg: ExperimentConfig) -> None:
    """
    Build one diverse pool of (case, trace, ground-truth) tuples by running a
    guided campaign against every profile, then score every detector on the
    *same* pool.  Sharing the pool makes the detector comparison a clean
    apples-to-apples ROC/PR study.
    """
    import json

    from boundsec.core.engine import CampaignConfig, FuzzingEngine, build_strategy
    out = cfg.out_dir / "exp2_detectors"
    out.mkdir(parents=True, exist_ok=True)
    _log(cfg, f"[exp2] detector quality -> {out}")

    detectors = {
        "heuristic": HeuristicDetector(),
        "canary": CanaryDetector(),
        "ensemble": EnsembleDetector([HeuristicDetector(), CanaryDetector()]),
    }

    pool = []  # (case, trace)
    seeds = load_seeds()
    for profile in cfg.profiles:
        for seed in range(max(3, cfg.n_seeds // 2)):
            target = GymAgent(profile, seed=seed)
            ccfg = CampaignConfig(budget=cfg.budget // 2, seed=seed,
                                  label=f"pool/{profile}")
            eng = FuzzingEngine(target, HeuristicDetector(),
                                build_strategy("coverage_guided", seeds, ccfg), ccfg)
            res = await eng.run()
            pool.extend((o.case, o.trace) for o in res.observations)

    _log(cfg, f"[exp2]   pool size = {len(pool)} traces")
    records = {"pool_size": len(pool), "detectors": {}}
    for name, det in detectors.items():
        rows = []
        for case, trace in pool:
            v = det.evaluate(case, trace)
            rows.append({
                "score": round(v.score, 4),
                "flagged": v.is_vulnerable,
                "gt_vulnerable": trace.ground_truth.is_vulnerable(),
                "gt_classes": [c.value for c in trace.ground_truth.vulnerabilities],
                "pred_classes": [c.value for c in v.vuln_classes],
                "latency_ms": round(v.latency_ms, 3),
            })
        records["detectors"][name] = rows
    (out / "detector_scores.json").write_text(json.dumps(records, indent=2))
    _log(cfg, f"[exp2] done ({len(detectors)} detectors x {len(pool)} traces)")


# ---------------------------------------------------------------------------
# Experiment 3 - defense effectiveness
# ---------------------------------------------------------------------------


async def exp3_defenses(cfg: ExperimentConfig) -> None:
    """
    Measure how much each defense layer reduces attack success.  We fix the
    strongest search (coverage-guided) and vary only the target's defenses:
    first each layer alone on top of a naive base, then cumulative stacking.
    Attack success = unique findings; the reduction is attributed to the layer.
    """
    import json
    out = cfg.out_dir / "exp3_defenses"
    out.mkdir(parents=True, exist_ok=True)
    _log(cfg, f"[exp3] defense effectiveness -> {out}")
    seeds = load_seeds()

    layers = ["injection_filter", "tool_allowlist", "path_canonicalization",
              "egress_filter", "input_decoding", "spotlighting", "rate_limit"]

    async def run_defense(defense: DefenseConfig, seed: int) -> int:
        target = GymAgent("naive", seed=seed, defenses=defense)
        # keep the base robustness of naive, vary only the defense stack
        ccfg = CampaignConfig(budget=cfg.budget, seed=seed)
        eng = FuzzingEngine(target, HeuristicDetector(),
                            build_strategy("coverage_guided", seeds, ccfg), ccfg)
        res = await eng.run()
        return res.n_findings

    results = {"single": {}, "cumulative": {}}

    # baseline: no defenses
    base = [await run_defense(DefenseConfig.none(), s) for s in range(cfg.n_seeds)]
    results["baseline"] = base
    _log(cfg, f"[exp3]   baseline (no defenses): mean={sum(base)/len(base):.1f}")

    # single-layer
    for layer in layers:
        dc = DefenseConfig(**{layer: True})
        vals = [await run_defense(dc, s) for s in range(cfg.n_seeds)]
        results["single"][layer] = vals
        _log(cfg, f"[exp3]   +{layer}: mean={sum(vals)/len(vals):.1f}")

    # cumulative stacking (in a fixed, sensible deployment order)
    order = ["injection_filter", "tool_allowlist", "path_canonicalization",
             "egress_filter", "input_decoding", "spotlighting", "rate_limit"]
    active: dict[str, bool] = {}
    for layer in order:
        active[layer] = True
        dc = DefenseConfig(**active)
        vals = [await run_defense(dc, s) for s in range(cfg.n_seeds)]
        results["cumulative"]["+".join(active.keys())] = vals
        _log(cfg, f"[exp3]   cumulative {len(active)}: mean={sum(vals)/len(vals):.1f}")

    (out / "defense_results.json").write_text(json.dumps(results, indent=2))
    _log(cfg, "[exp3] done")


# ---------------------------------------------------------------------------
# Experiment 4 - coverage-dimension ablation
# ---------------------------------------------------------------------------


async def exp4_ablation(cfg: ExperimentConfig) -> None:
    """
    Turn off one coverage dimension at a time (and run a coverage-free control)
    to measure each dimension's contribution to bug discovery.
    """
    import json
    out = cfg.out_dir / "exp4_ablation"
    out.mkdir(parents=True, exist_ok=True)
    _log(cfg, f"[exp4] coverage-dimension ablation -> {out}")

    configs = {"all": tuple(DIMENSIONS)}
    for d in DIMENSIONS:
        configs[f"no_{d}"] = tuple(x for x in DIMENSIONS if x != d)
    configs["action_only"] = ("action",)
    configs["none"] = ()  # guidance with an inert (always-zero) coverage signal

    # Two metrics per config: bug recall (findings) and, non-circularly, the
    # fraction of the FULL behavioural space explored (a fixed yardstick that
    # every config is scored against regardless of which dims guided the search).
    results: dict[str, dict] = {}
    for name, dims in configs.items():
        by_profile: dict[str, dict] = {}
        for profile in ["basic", "hardened"]:
            finds, yard = [], []
            for seed in range(cfg.n_seeds):
                # Pass dims verbatim: () means "no coverage guidance" (the control),
                # a non-empty tuple restricts guidance to those dimensions. Do NOT
                # coerce () to None (which would silently enable ALL dimensions).
                f, y = await _ablation_campaign(profile, seed, cfg.budget, dims)
                finds.append(f)
                yard.append(y)
            by_profile[profile] = {"findings": finds, "yardstick_coverage": yard}
        results[name] = by_profile
        _log(cfg, f"[exp4]   {name}: " + ", ".join(
            f"{p}=(bugs {sum(v['findings'])/len(v['findings']):.1f}, "
            f"cov {sum(v['yardstick_coverage'])/len(v['yardstick_coverage']):.0f})"
            for p, v in by_profile.items()))

    (out / "ablation_results.json").write_text(json.dumps(results, indent=2))
    _log(cfg, "[exp4] done")


async def _ablation_campaign(profile: str, seed: int, budget: int,
                             dims) -> tuple[int, int]:
    """
    Run a campaign whose search is guided by ``dims`` (None = all; () = none),
    while measuring how much of the FULL five-dimension behavioural space it
    reached.  The yardstick map sees every trace but never steers the search,
    so the comparison across configs is non-circular: it asks whether guiding
    with a subset of coverage still drives the search to explore the whole space.
    """
    from boundsec.core.coverage import DIMENSIONS as ALL_DIMS
    from boundsec.core.coverage import CoverageMap
    seeds = load_seeds()
    target = GymAgent(profile, seed=seed)
    ccfg = CampaignConfig(budget=budget, seed=seed, dimensions=dims)
    eng = FuzzingEngine(target, HeuristicDetector(),
                        build_strategy("coverage_guided", seeds, ccfg), ccfg)
    res = await eng.run()
    yardstick = CoverageMap(dimensions=ALL_DIMS)
    for obs in res.observations:
        yardstick.update(obs.trace)
    return res.n_findings, yardstick.size


# ---------------------------------------------------------------------------
# Driver
# ---------------------------------------------------------------------------


async def run_all(cfg: ExperimentConfig) -> None:
    t0 = time.monotonic()
    await exp1_strategy(cfg)
    await exp2_detectors(cfg)
    await exp3_defenses(cfg)
    await exp4_ablation(cfg)
    _log(cfg, f"\n[all] full suite done in {time.monotonic()-t0:.1f}s -> {cfg.out_dir}")


def main(budget: int = 600, n_seeds: int = 10, out: str = "results",
         only: str | None = None) -> None:
    cfg = ExperimentConfig(budget=budget, n_seeds=n_seeds, out_dir=Path(out))
    runner = {"exp1": exp1_strategy, "exp2": exp2_detectors,
              "exp3": exp3_defenses, "exp4": exp4_ablation}
    if only and only in runner:
        asyncio.run(runner[only](cfg))
    else:
        asyncio.run(run_all(cfg))


if __name__ == "__main__":
    import typer
    typer.run(main)
