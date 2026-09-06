"""
BoundSec - Results persistence.

A campaign produces a lot of per-query rows; the analysis and figures need them
in a stable, versioned, self-describing form.  This module defines that schema
and the (de)serialisation to JSON.  Every results file records the exact config
(strategy, profile, seed, budget, coverage dimensions) so a figure can be traced
back to the run that produced it and regenerated deterministically.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from pathlib import Path

from boundsec.core.engine import CampaignResult

SCHEMA_VERSION = "2.0"


@dataclass
class QueryRow:
    """One flattened observation - the atomic unit the analysis consumes."""

    step: int
    case_id: str
    seed_id: str
    technique: str
    objective: str | None
    source: str
    generation: int
    lineage: list[str]
    response_mode: str
    new_coverage: int
    total_coverage: int
    detector_score: float
    is_flagged: bool
    pred_classes: list[str]
    gt_available: bool
    gt_vulnerable: bool
    gt_classes: list[str]
    gt_defenses: list[str]
    latency_ms: float
    is_new_finding: bool


@dataclass
class CampaignRecord:
    schema_version: str
    strategy: str
    profile: str
    target: str
    seed: int
    budget: int
    dimensions: list[str]
    queries_used: int
    wall_time_s: float
    n_unique_findings: int
    final_coverage: int
    corpus_size: int
    coverage_history: list[int]
    scheduler_stats: list[dict] | None
    rows: list[dict]
    finding_keys: list[str]

    def to_json(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(asdict(self), indent=2))

    @staticmethod
    def from_json(path: Path) -> CampaignRecord:
        d = json.loads(Path(path).read_text())
        return CampaignRecord(**d)

    # -- convenience views for analysis ---------------------------------

    def scores(self) -> list[float]:
        return [r["detector_score"] for r in self.rows]

    def gt_labels(self) -> list[int]:
        return [int(r["gt_vulnerable"]) for r in self.rows]

    def finding_steps(self) -> list[int]:
        return sorted(r["step"] for r in self.rows if r["is_new_finding"])


def record_from_result(result: CampaignResult, profile: str, target: str) -> CampaignRecord:
    finding_keys = set(result.unique_findings.keys())
    seen: set[str] = set()
    rows: list[dict] = []

    # Recompute which observation first realised each unique finding.
    from boundsec.core.engine import _finding_key
    for obs in result.observations:
        v = obs.verdict
        gt = obs.trace.ground_truth
        is_new = False
        if v.is_vulnerable:
            key = _finding_key(obs)
            if key in finding_keys and key not in seen:
                seen.add(key)
                is_new = True
        rows.append(asdict(QueryRow(
            step=obs.step,
            case_id=obs.case.case_id,
            seed_id=obs.case.seed_id,
            technique=obs.case.technique.value,
            objective=obs.case.objective.value if obs.case.objective else None,
            source=obs.case.source,
            generation=obs.case.generation,
            lineage=obs.case.lineage,
            response_mode=obs.response_mode.value,
            new_coverage=obs.new_coverage,
            total_coverage=obs.total_coverage,
            detector_score=round(v.score, 4),
            is_flagged=v.is_vulnerable,
            pred_classes=[c.value for c in v.vuln_classes],
            gt_available=gt.available,
            gt_vulnerable=gt.is_vulnerable(),
            gt_classes=[c.value for c in gt.vulnerabilities],
            gt_defenses=gt.defense_layers_triggered,
            latency_ms=round(obs.trace.latency_ms, 2),
            is_new_finding=is_new,
        )))

    cfg = result.config
    return CampaignRecord(
        schema_version=SCHEMA_VERSION,
        strategy=result.strategy,
        profile=profile,
        target=target,
        seed=cfg.seed,
        budget=cfg.budget,
        dimensions=list(cfg.dimensions) if cfg.dimensions else ["all"],
        queries_used=result.queries_used,
        wall_time_s=round(result.wall_time_s, 3),
        n_unique_findings=result.n_findings,
        final_coverage=result.final_coverage,
        corpus_size=result.corpus_size,
        coverage_history=result.coverage_history,
        scheduler_stats=result.scheduler_stats,
        rows=rows,
        finding_keys=sorted(finding_keys),
    )


def load_all(results_dir: Path) -> list[CampaignRecord]:
    return [CampaignRecord.from_json(p) for p in sorted(Path(results_dir).glob("*.json"))]
