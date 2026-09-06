"""
BoundSec - Evaluation metrics.

Threshold-free detector metrics (ROC-AUC, PR-AUC, calibration), search-strategy
metrics (bug recall vs the measurable ceiling, discovery curves, restricted AUC),
and the non-parametric statistics used to make claims defensible: bootstrap
confidence intervals, the Mann-Whitney U test with a rank-biserial effect size,
and Vargha-Delaney A12 (the standard effect size for randomised fuzzing
experiments, Arcuri & Briand 2014).

Everything here is dependency-light (numpy only) and deterministic, so a claim
in the paper can be regenerated bit-for-bit from a results file.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np

# ---------------------------------------------------------------------------
# Detector metrics (threshold-free)
# ---------------------------------------------------------------------------


def roc_curve(scores: np.ndarray, labels: np.ndarray):
    """Return (fpr, tpr, thresholds) with no sklearn dependency."""
    order = np.argsort(-scores, kind="mergesort")
    s, y = scores[order], labels[order].astype(float)
    P, N = y.sum(), (1 - y).sum()
    if P == 0 or N == 0:
        return np.array([0, 1.0]), np.array([0, 1.0]), np.array([np.inf, -np.inf])
    tp = np.cumsum(y)
    fp = np.cumsum(1 - y)
    # collapse ties at equal score
    distinct = np.r_[np.where(np.diff(s))[0], s.size - 1]
    tpr = np.r_[0, tp[distinct] / P]
    fpr = np.r_[0, fp[distinct] / N]
    thr = np.r_[np.inf, s[distinct]]
    return fpr, tpr, thr


def auc(x: np.ndarray, y: np.ndarray) -> float:
    """Trapezoidal area under a curve sorted by x."""
    order = np.argsort(x, kind="mergesort")
    return float(np.trapezoid(y[order], x[order]))


def roc_auc(scores: np.ndarray, labels: np.ndarray) -> float:
    """ROC-AUC via the Mann-Whitney U identity (robust to ties)."""
    labels = labels.astype(bool)
    pos, neg = scores[labels], scores[~labels]
    if pos.size == 0 or neg.size == 0:
        return float("nan")
    ranks = _rankdata(np.concatenate([pos, neg]))
    r_pos = ranks[: pos.size].sum()
    u = r_pos - pos.size * (pos.size + 1) / 2
    return float(u / (pos.size * neg.size))


def pr_curve(scores: np.ndarray, labels: np.ndarray):
    order = np.argsort(-scores, kind="mergesort")
    y = labels[order].astype(float)
    tp = np.cumsum(y)
    fp = np.cumsum(1 - y)
    P = y.sum()
    if P == 0:
        return np.array([0.0, 1.0]), np.array([1.0, 1.0])
    precision = tp / np.maximum(tp + fp, 1)
    recall = tp / P
    return np.r_[recall, [1.0]], np.r_[precision, [tp[-1] / max(tp[-1] + fp[-1], 1)]]


def average_precision(scores: np.ndarray, labels: np.ndarray) -> float:
    order = np.argsort(-scores, kind="mergesort")
    y = labels[order].astype(float)
    if y.sum() == 0:
        return float("nan")
    tp = np.cumsum(y)
    precision = tp / (np.arange(y.size) + 1)
    return float((precision * y).sum() / y.sum())


def confusion_at(scores: np.ndarray, labels: np.ndarray, thr: float) -> dict:
    pred = scores >= thr
    y = labels.astype(bool)
    tp = int((pred & y).sum())
    fp = int((pred & ~y).sum())
    fn = int((~pred & y).sum())
    tn = int((~pred & ~y).sum())
    prec = tp / (tp + fp) if tp + fp else 0.0
    rec = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
    return {"threshold": thr, "tp": tp, "fp": fp, "fn": fn, "tn": tn,
            "precision": prec, "recall": rec, "f1": f1,
            "fpr": fp / (fp + tn) if fp + tn else 0.0}


def best_f1_threshold(scores: np.ndarray, labels: np.ndarray) -> dict:
    cands = np.unique(scores)
    best = {"f1": -1.0}
    for t in cands:
        c = confusion_at(scores, labels, t)
        if c["f1"] > best["f1"]:
            best = c
    return best


def calibration_bins(scores: np.ndarray, labels: np.ndarray, n_bins: int = 10):
    """Reliability-diagram data + Expected Calibration Error."""
    edges = np.linspace(0, 1, n_bins + 1)
    xs, ys, counts = [], [], []
    ece = 0.0
    for i in range(n_bins):
        lo, hi = edges[i], edges[i + 1]
        mask = (scores >= lo) & (scores < hi if i < n_bins - 1 else scores <= hi)
        if mask.sum() == 0:
            continue
        conf = scores[mask].mean()
        acc = labels[mask].mean()
        xs.append(conf); ys.append(acc); counts.append(int(mask.sum()))
        ece += mask.mean() * abs(acc - conf)
    return {"conf": xs, "acc": ys, "counts": counts, "ece": float(ece)}


# ---------------------------------------------------------------------------
# Non-parametric statistics
# ---------------------------------------------------------------------------


def _rankdata(a: np.ndarray) -> np.ndarray:
    order = np.argsort(a, kind="mergesort")
    ranks = np.empty_like(order, dtype=float)
    sa = a[order]
    i = 0
    n = a.size
    while i < n:
        j = i
        while j < n and sa[j] == sa[i]:
            j += 1
        ranks[order[i:j]] = (i + j - 1) / 2.0 + 1.0
        i = j
    return ranks


def mann_whitney_u(a: np.ndarray, b: np.ndarray) -> dict:
    """Two-sided Mann-Whitney U with a normal approximation + rank-biserial r."""
    a, b = np.asarray(a, float), np.asarray(b, float)
    n1, n2 = a.size, b.size
    if n1 == 0 or n2 == 0:
        return {"u": float("nan"), "p": float("nan"), "rank_biserial": float("nan")}
    ranks = _rankdata(np.concatenate([a, b]))
    r1 = ranks[:n1].sum()
    u1 = r1 - n1 * (n1 + 1) / 2
    u2 = n1 * n2 - u1
    u = min(u1, u2)
    mu = n1 * n2 / 2
    # tie-corrected standard deviation
    _, counts = np.unique(np.concatenate([a, b]), return_counts=True)
    tie = (counts**3 - counts).sum()
    n = n1 + n2
    sigma = np.sqrt(n1 * n2 / 12 * ((n + 1) - tie / (n * (n - 1))))
    z = (u - mu) / sigma if sigma > 0 else 0.0
    p = 2 * (1 - _norm_cdf(abs(z)))
    r_rb = 1 - 2 * u / (n1 * n2)  # rank-biserial correlation
    return {"u": float(u1), "p": float(min(1.0, p)), "z": float(z),
            "rank_biserial": float(r_rb)}


def vargha_delaney_a12(a: np.ndarray, b: np.ndarray) -> float:
    """
    Vargha-Delaney A12: P(a > b) + 0.5 P(a = b).  The standard fuzzing effect
    size; 0.5 = no effect, >0.71 conventionally "large".
    """
    a, b = np.asarray(a, float), np.asarray(b, float)
    if a.size == 0 or b.size == 0:
        return float("nan")
    ranks = _rankdata(np.concatenate([a, b]))
    r1 = ranks[: a.size].sum()
    return float((r1 / a.size - (a.size + 1) / 2) / b.size)


def bootstrap_ci(x: np.ndarray, n_boot: int = 5000, alpha: float = 0.05,
                 seed: int = 0, stat=np.mean) -> tuple[float, float, float]:
    """Percentile bootstrap CI for a statistic of a 1-D sample."""
    x = np.asarray(x, float)
    if x.size == 0:
        return (float("nan"),) * 3
    rng = np.random.default_rng(seed)
    idx = rng.integers(0, x.size, size=(n_boot, x.size))
    boots = stat(x[idx], axis=1)
    lo, hi = np.percentile(boots, [100 * alpha / 2, 100 * (1 - alpha / 2)])
    return float(stat(x)), float(lo), float(hi)


def _norm_cdf(z: float) -> float:
    import math
    return 0.5 * (1 + math.erf(z / math.sqrt(2)))


# ---------------------------------------------------------------------------
# Search-strategy metrics
# ---------------------------------------------------------------------------


def discovery_curve(steps: list[int], budget: int) -> np.ndarray:
    """Cumulative unique-findings count indexed by query step (0..budget)."""
    curve = np.zeros(budget + 1)
    for s in steps:
        if s <= budget:
            curve[s:] += 1
    return curve


def normalized_auc(curve: np.ndarray) -> float:
    """Area under a discovery curve, normalised to [0,1] by (budget x max)."""
    if curve.size < 2 or curve.max() == 0:
        return 0.0
    return float(np.trapezoid(curve) / ((curve.size - 1) * curve.max()))


@dataclass
class StrategyComparison:
    """A vs B on a paired per-seed metric, with test + effect sizes."""

    name_a: str
    name_b: str
    mean_a: float
    mean_b: float
    ci_a: tuple[float, float]
    ci_b: tuple[float, float]
    p_value: float
    a12: float
    rank_biserial: float
    lift_pct: float

    def as_dict(self) -> dict:
        return {
            "a": self.name_a, "b": self.name_b,
            "mean_a": round(self.mean_a, 3), "mean_b": round(self.mean_b, 3),
            "ci_a": [round(c, 3) for c in self.ci_a],
            "ci_b": [round(c, 3) for c in self.ci_b],
            "p_value": round(self.p_value, 5), "a12": round(self.a12, 3),
            "rank_biserial": round(self.rank_biserial, 3),
            "lift_pct": round(self.lift_pct, 1),
        }


def compare_strategies(a: list[float], b: list[float],
                       name_a: str, name_b: str, seed: int = 0) -> StrategyComparison:
    a_arr, b_arr = np.asarray(a, float), np.asarray(b, float)
    mw = mann_whitney_u(a_arr, b_arr)
    ma, la, ha = bootstrap_ci(a_arr, seed=seed)
    mb, lb, hb = bootstrap_ci(b_arr, seed=seed)
    lift = (ma - mb) / mb * 100 if mb else float("inf")
    return StrategyComparison(
        name_a=name_a, name_b=name_b, mean_a=ma, mean_b=mb,
        ci_a=(la, ha), ci_b=(lb, hb), p_value=mw["p"],
        a12=vargha_delaney_a12(a_arr, b_arr),
        rank_biserial=mw["rank_biserial"], lift_pct=lift)
