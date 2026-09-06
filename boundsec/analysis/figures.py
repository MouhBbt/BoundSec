"""
BoundSec - Figure generation.

Turns the recorded campaign results into the publication figure set.  Every
figure is regenerated from the results directory, so nothing is drawn by hand
and each panel is traceable to a run.  The functions are grouped by experiment
and orchestrated by :func:`generate_all`, which also writes ``summary.json`` -
the machine-readable digest the README and the web report read their headline
numbers from, so prose and figures can never disagree.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np

from boundsec.analysis import metrics as M
from boundsec.analysis import style as S
from boundsec.analysis.results import CampaignRecord, load_all

S.install()


# ---------------------------------------------------------------------------
# Loading helpers
# ---------------------------------------------------------------------------


def _group(records: list[CampaignRecord]):
    """(strategy, profile) -> list[record]."""
    g: dict[tuple[str, str], list[CampaignRecord]] = defaultdict(list)
    for r in records:
        g[(r.strategy, r.profile)].append(r)
    return g


def _findings_by(records, strategy, profile) -> list[int]:
    return [r.n_unique_findings for r in records
            if r.strategy == strategy and r.profile == profile]


def compute_ceilings(records) -> dict[str, int]:
    """
    Empirical reachable-bug set per profile: the union of every distinct finding
    key discovered by *any* strategy on *any* seed.  This is the denominator for
    recall - the standard fuzzing metric when the true bug count is unknown
    (here it approximates the set of construction-reachable vulnerabilities).
    """
    ceil: dict[str, set] = {}
    for r in records:
        ceil.setdefault(r.profile, set()).update(r.finding_keys)
    return {p: len(k) for p, k in ceil.items()}


def _recall_by(records, strategy, profile, ceiling: int) -> list[float]:
    if ceiling <= 0:
        return [0.0]
    return [r.n_unique_findings / ceiling * 100 for r in records
            if r.strategy == strategy and r.profile == profile]


# ---------------------------------------------------------------------------
# Figure 1 - strategy comparison bars
# ---------------------------------------------------------------------------


def fig_strategy_bars(records, out: Path) -> dict:
    """Headline: bug recall against the per-profile reachable set, plus raw counts."""
    profiles = [p for p in S.PROFILE_ORDER if any(r.profile == p for r in records)]
    strategies = [s for s in S.STRATEGY_ORDER if any(r.strategy == s for r in records)]
    ceilings = compute_ceilings(records)
    summary = {"ceilings": ceilings}

    fig, (axR, axC) = plt.subplots(1, 2, figsize=(13.2, 5.8),
                                   gridspec_kw={"width_ratios": [1.15, 1], "wspace": 0.22})
    fig.subplots_adjust(top=0.80)
    n_s = len(strategies)
    width = 0.8 / n_s
    x = np.arange(len(profiles))

    for i, strat in enumerate(strategies):
        rec_means, rec_lo, rec_hi = [], [], []
        cnt_means, cnt_lo, cnt_hi = [], [], []
        for prof in profiles:
            ceil = ceilings.get(prof, 0)
            rv = np.array(_recall_by(records, strat, prof, ceil), float)
            m, lo, hi = M.bootstrap_ci(rv) if rv.size else (0, 0, 0)
            rec_means.append(m); rec_lo.append(m - lo); rec_hi.append(hi - m)
            cv = np.array(_findings_by(records, strat, prof), float)
            cm, clo, chi = M.bootstrap_ci(cv) if cv.size else (0, 0, 0)
            cnt_means.append(cm); cnt_lo.append(cm - clo); cnt_hi.append(chi - cm)
            summary[f"{strat}/{prof}"] = {
                "recall_pct": round(m, 1), "recall_ci": [round(lo, 1), round(hi, 1)],
                "mean_findings": round(cm, 2), "n": int(cv.size)}
        off = (i - (n_s - 1) / 2) * width
        c = S.strat_color(strat)
        b1 = axR.bar(x + off, rec_means, width * 0.92, yerr=[rec_lo, rec_hi],
                     color=c, label=S.strat_label(strat), edgecolor=S.SURFACE,
                     linewidth=0.6, error_kw={"elinewidth": 1, "capsize": 2.5, "ecolor": S.INK2}, zorder=3)
        for b, m in zip(b1, rec_means):
            axR.text(b.get_x() + b.get_width() / 2, m + 1.6, f"{m:.0f}",
                     ha="center", va="bottom", fontsize=7.8, color=S.INK2, fontweight="bold")
        axC.bar(x + off, cnt_means, width * 0.92, yerr=[cnt_lo, cnt_hi], color=c,
                label=S.strat_label(strat), edgecolor=S.SURFACE, linewidth=0.6,
                error_kw={"elinewidth": 1, "capsize": 2.5, "ecolor": S.INK2}, zorder=3)

    axR.set_xticks(x); axR.set_xticklabels([p.capitalize() for p in profiles])
    # Figure-level headline (spans both panels, no collision with axis titles).
    fig.suptitle("Coverage-guided search recovers far more of the reachable vulnerabilities",
                 x=0.075, y=0.965, ha="left", fontsize=15, fontweight="bold", color=S.INK)
    fig.text(0.075, 0.905,
             "Four search strategies · four agent hardening levels · 15 seeds each · fixed query budget",
             ha="left", fontsize=10, color=S.MUTED)

    axR.set_xticks(x); axR.set_xticklabels([p.capitalize() for p in profiles])
    axR.set_ylabel("Bug recall vs. reachable set (%)")
    axR.set_xlabel("Target agent hardening level →")
    axR.set_ylim(0, 105)
    axR.set_title("Recall — % of reachable bugs found", loc="left", fontsize=11.5, pad=8)
    for xi, prof in zip(x, profiles):
        axR.text(xi, -13, f"|set|={ceilings.get(prof,0)}", ha="center",
                 fontsize=7.6, color=S.MUTED)

    axC.set_xticks(x); axC.set_xticklabels([p.capitalize() for p in profiles])
    axC.set_ylabel("Distinct vulnerabilities found (count)")
    axC.set_xlabel("Target agent hardening level →")
    axC.set_title("Absolute counts — same runs, unnormalised", loc="left", fontsize=11.5, pad=8)
    axC.legend(loc="upper right", ncol=1, fontsize=8.4, framealpha=0.9,
               facecolor=S.SURFACE, edgecolor=S.GRID)
    axC.margins(y=0.14)
    fig.savefig(out / "fig1_strategy_comparison.png", bbox_inches="tight", facecolor=S.SURFACE)
    plt.close(fig)
    return summary


# ---------------------------------------------------------------------------
# Figure 2 - discovery curves (small multiples per profile)
# ---------------------------------------------------------------------------


def fig_discovery_curves(records, out: Path) -> None:
    profiles = [p for p in S.PROFILE_ORDER if any(r.profile == p for r in records)]
    strategies = [s for s in S.STRATEGY_ORDER if any(r.strategy == s for r in records)]
    n = len(profiles)
    fig, axes = plt.subplots(1, n, figsize=(4.4 * n, 4.2), sharey=True)
    if n == 1:
        axes = [axes]
    budget = max(r.budget for r in records)

    for ax, prof in zip(axes, profiles):
        for strat in strategies:
            curves = []
            for r in records:
                if r.strategy == strat and r.profile == prof:
                    curves.append(M.discovery_curve(r.finding_steps(), budget))
            if not curves:
                continue
            arr = np.vstack(curves)
            mean = arr.mean(0)
            lo = np.percentile(arr, 2.5, axis=0)
            hi = np.percentile(arr, 97.5, axis=0)
            xs = np.arange(budget + 1)
            c = S.strat_color(strat)
            ax.fill_between(xs, lo, hi, color=c, alpha=0.13, linewidth=0)
            ax.plot(xs, mean, color=c, linewidth=2.0, label=S.strat_label(strat))
        ax.set_title(prof.capitalize(), loc="left", fontsize=11)
        ax.set_xlabel("Queries to target")
        ax.margins(x=0)
    axes[0].set_ylabel("Cumulative unique findings")
    axes[-1].legend(loc="upper left", fontsize=8.5)
    fig.suptitle("Vulnerability discovery vs. query budget",
                 x=0.09, y=1.01, ha="left", fontsize=13, fontweight="bold")
    S.savefig(fig, out / "fig2_discovery_curves.png")


# ---------------------------------------------------------------------------
# Figure 3 - coverage growth
# ---------------------------------------------------------------------------


def fig_coverage_growth(records, out: Path, profile: str = "hardened") -> None:
    strategies = [s for s in S.STRATEGY_ORDER if any(r.strategy == s for r in records)]
    fig, ax = plt.subplots(figsize=(8.4, 4.8))
    for strat in strategies:
        curves = [np.asarray(r.coverage_history) for r in records
                  if r.strategy == strat and r.profile == profile and r.coverage_history]
        if not curves:
            continue
        L = min(len(c) for c in curves)
        arr = np.vstack([c[:L] for c in curves])
        mean = arr.mean(0)
        xs = np.arange(L)
        c = S.strat_color(strat)
        ax.fill_between(xs, arr.min(0), arr.max(0), color=c, alpha=0.10, linewidth=0)
        ax.plot(xs, mean, color=c, linewidth=2.0, label=S.strat_label(strat))
    ax.set_xlabel("Queries to target")
    ax.set_ylabel("Behavioural coverage (bitmap slots)")
    S.title_block(ax, "Behavioural coverage growth",
                  f"Agent profile: {profile} · shaded = min–max over seeds")
    ax.legend(loc="lower right")
    ax.margins(x=0)
    S.savefig(fig, out / "fig3_coverage_growth.png")


# ---------------------------------------------------------------------------
# Figure 4 - effect sizes (A12) vs the hero
# ---------------------------------------------------------------------------


def fig_effect_sizes(records, out: Path) -> dict:
    profiles = [p for p in S.PROFILE_ORDER if any(r.profile == p for r in records)]
    baselines = ["static_replay", "random_mutation", "guided_no_bandit"]
    fig, ax = plt.subplots(figsize=(8.6, 4.8))
    summary = {}
    ypos = []
    ylabels = []
    y = 0
    for prof in profiles:
        hero = np.array(_findings_by(records, "coverage_guided", prof), float)
        for base in baselines:
            b = np.array(_findings_by(records, base, prof), float)
            if hero.size == 0 or b.size == 0:
                continue
            a12 = M.vargha_delaney_a12(hero, b)
            cmp = M.compare_strategies(list(hero), list(b), "coverage_guided", base)
            summary[f"{prof}/{base}"] = {"a12": round(a12, 3),
                                         "p": round(cmp.p_value, 4),
                                         "lift_pct": round(cmp.lift_pct, 1)}
            color = S.strat_color(base)
            sig = cmp.p_value < 0.05
            ax.plot([0.5, a12], [y, y], color=S.GRID, linewidth=1.0, zorder=1)
            ax.scatter([a12], [y], s=90 if sig else 55,
                       color=color, edgecolor=S.SURFACE, linewidth=1.0, zorder=3,
                       marker="o" if sig else "D")
            ylabels.append(f"{prof}  vs  {S.strat_label(base)}")
            ypos.append(y)
            y += 1
        y += 0.6

    ax.axvline(0.5, color=S.INK2, linewidth=1.0, linestyle=(0, (4, 3)))
    for xv, lab in [(0.71, "large"), (0.5, "no effect")]:
        ax.axvline(xv, color=S.MUTED, linewidth=0.7, linestyle=":", alpha=0.7)
    ax.set_yticks(ypos)
    ax.set_yticklabels(ylabels, fontsize=8.6)
    ax.set_xlim(0.28, 1.03)
    ax.set_xlabel("Vargha–Delaney Â₁₂  (P coverage-guided finds more)")
    ax.invert_yaxis()
    S.title_block(ax, "Effect size of coverage-guided search vs. each baseline",
                  "● p<0.05 (Mann–Whitney) · ◆ not significant · 0.71 = ‘large’ threshold")
    S.despine(ax, left=False)
    S.savefig(fig, out / "fig4_effect_sizes.png")
    return summary


# ---------------------------------------------------------------------------
# Detector figures (exp2)
# ---------------------------------------------------------------------------


def _load_detector_scores(results_dir: Path) -> dict:
    p = results_dir / "exp2_detectors" / "detector_scores.json"
    return json.loads(p.read_text()) if p.exists() else {}


def fig_detector_roc_pr(results_dir: Path, out: Path) -> dict:
    data = _load_detector_scores(results_dir)
    if not data:
        return {}
    dets = data["detectors"]
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11.2, 4.9))
    summary = {}
    for name, rows in dets.items():
        scores = np.array([r["score"] for r in rows])
        labels = np.array([int(r["gt_vulnerable"]) for r in rows])
        if labels.sum() == 0 or labels.sum() == labels.size:
            continue
        fpr, tpr, _ = M.roc_curve(scores, labels)
        rec, prec = M.pr_curve(scores, labels)
        roc = M.roc_auc(scores, labels)
        ap = M.average_precision(scores, labels)
        best = M.best_f1_threshold(scores, labels)
        summary[name] = {"roc_auc": round(roc, 4), "pr_auc": round(ap, 4),
                         "best_f1": round(best["f1"], 3),
                         "precision": round(best["precision"], 3),
                         "recall": round(best["recall"], 3),
                         "threshold": round(best["threshold"], 3),
                         "n": len(rows), "prevalence": round(labels.mean(), 3)}
        c = S.DETECTOR_COLORS.get(name, S.BLUE)
        # Dash the ensemble so it does not fully occlude an identical component.
        ls = (0, (6, 3)) if name == "ensemble" else "-"
        lw = 2.6 if name == "ensemble" else 2.0
        ax1.plot(fpr, tpr, color=c, linewidth=lw, linestyle=ls, label=f"{name} (AUC={roc:.3f})")
        ax2.plot(rec, prec, color=c, linewidth=lw, linestyle=ls, label=f"{name} (AP={ap:.3f})")

    ax1.plot([0, 1], [0, 1], color=S.MUTED, linewidth=0.9, linestyle=":")
    ax1.set_xlabel("False positive rate"); ax1.set_ylabel("True positive rate")
    S.title_block(ax1, "ROC", "Detector discrimination vs. gym ground truth")
    ax1.legend(loc="lower right", fontsize=8.6); ax1.set_xlim(0, 1); ax1.set_ylim(0, 1.02)

    prev = np.mean([int(r["gt_vulnerable"]) for r in next(iter(dets.values()))])
    ax2.axhline(prev, color=S.MUTED, linewidth=0.8, linestyle=":", label=f"prevalence={prev:.2f}")
    ax2.set_xlabel("Recall"); ax2.set_ylabel("Precision")
    S.title_block(ax2, "Precision–Recall", "Robust to class imbalance")
    ax2.legend(loc="lower left", fontsize=8.6); ax2.set_xlim(0, 1); ax2.set_ylim(0, 1.02)
    S.savefig(fig, out / "fig5_detector_roc_pr.png")
    return summary


def fig_detector_calibration(results_dir: Path, out: Path) -> None:
    data = _load_detector_scores(results_dir)
    if not data:
        return
    fig, ax = plt.subplots(figsize=(6.4, 5.4))
    ax.plot([0, 1], [0, 1], color=S.MUTED, linestyle=":", linewidth=1.0, label="perfect")
    for name, rows in data["detectors"].items():
        scores = np.array([r["score"] for r in rows])
        labels = np.array([int(r["gt_vulnerable"]) for r in rows])
        cal = M.calibration_bins(scores, labels, n_bins=10)
        if not cal["conf"]:
            continue
        c = S.DETECTOR_COLORS.get(name, S.BLUE)
        sizes = 40 + 260 * np.array(cal["counts"]) / max(cal["counts"])
        ax.plot(cal["conf"], cal["acc"], color=c, linewidth=1.6,
                label=f"{name} (ECE={cal['ece']:.3f})", zorder=2)
        ax.scatter(cal["conf"], cal["acc"], s=sizes, color=c,
                   edgecolor=S.SURFACE, linewidth=0.8, zorder=3, alpha=0.9)
    ax.set_xlabel("Mean predicted score"); ax.set_ylabel("Empirical vulnerability rate")
    ax.set_xlim(0, 1); ax.set_ylim(0, 1)
    S.title_block(ax, "Detector calibration (reliability)",
                  "Marker size ∝ bin count · closer to diagonal = better calibrated")
    ax.legend(loc="upper left", fontsize=8.8)
    S.savefig(fig, out / "fig6_detector_calibration.png")


# ---------------------------------------------------------------------------
# Operator / technique figures (from exp1 rows)
# ---------------------------------------------------------------------------


def fig_operator_effectiveness(records, out: Path) -> None:
    from boundsec.core.operators import all_operators
    fam_color = {}
    fams = sorted({op.family.value for op in all_operators()})
    palette = [S.BLUE, S.ORANGE, S.AQUA, S.YELLOW, S.MAGENTA, S.VIOLET, S.GREEN,
               S.RED, "#7a8b99", "#b5651d", "#2c9c9c", "#9a6fb0", "#c04a6e", "#557a3f"]
    for i, f in enumerate(fams):
        fam_color[f] = palette[i % len(palette)]

    # Attribute each new finding to the last mutation operator in its lineage.
    bug_by_op: Counter = Counter()
    tries_by_op: Counter = Counter()
    op_family: dict[str, str] = {}
    for op in all_operators():
        op_family[op.name] = op.family.value
    for r in records:
        if r.strategy != "coverage_guided":
            continue
        for row in r.rows:
            if row["lineage"]:
                op = row["lineage"][-1]
                if op.startswith("x:"):
                    op = "crossover"
                tries_by_op[op] += 1
                if row["is_new_finding"]:
                    bug_by_op[op] += 1

    ops = [o for o in bug_by_op] or list(tries_by_op)
    ops = sorted(ops, key=lambda o: bug_by_op[o])
    fig, ax = plt.subplots(figsize=(8.8, max(4.5, 0.42 * len(ops))))
    yvals = np.arange(len(ops))
    colors = [fam_color.get(op_family.get(o, ""), S.GREY) for o in ops]
    widths = [bug_by_op[o] for o in ops]
    ax.barh(yvals, widths, color=colors, edgecolor=S.SURFACE, linewidth=0.6, zorder=3)
    for y, o, w in zip(yvals, ops, widths):
        rate = bug_by_op[o] / tries_by_op[o] if tries_by_op[o] else 0
        ax.text(w + max(widths) * 0.01 + 0.2, y, f"{w}  ({rate:.0%})",
                va="center", fontsize=8.2, color=S.INK2)
    ax.set_yticks(yvals); ax.set_yticklabels(ops, fontsize=8.6)
    ax.set_xlabel("Unique findings credited (label shows hit-rate per attempt)")
    S.title_block(ax, "Which mutation operators discover vulnerabilities",
                  "Credited to the final operator in each finding's lineage · colour = attack family")
    from matplotlib.patches import Patch
    used_fams = sorted({op_family.get(o, "") for o in ops if op_family.get(o)})
    ax.legend(handles=[Patch(color=fam_color[f], label=f) for f in used_fams],
              loc="lower right", fontsize=7.6, ncol=1)
    ax.margins(y=0.01)
    S.savefig(fig, out / "fig7_operator_effectiveness.png")


def fig_technique_outcome_heatmap(records, out: Path) -> None:
    from boundsec.core.types import VulnClass
    techniques = sorted({row["technique"] for r in records for row in r.rows})
    classes = [v.value for v in VulnClass]
    counts = np.zeros((len(techniques), len(classes)))
    ti = {t: i for i, t in enumerate(techniques)}
    ci = {c: i for i, c in enumerate(classes)}
    for r in records:
        for row in r.rows:
            if row["is_new_finding"]:
                for gc in row["gt_classes"]:
                    if gc in ci:
                        counts[ti[row["technique"]], ci[gc]] += 1
    # drop all-zero classes
    keep = counts.sum(0) > 0
    counts = counts[:, keep]
    classes = [c for c, k in zip(classes, keep) if k]

    fig, ax = plt.subplots(figsize=(1.0 + 0.75 * len(classes), 0.9 + 0.5 * len(techniques)))
    im = ax.imshow(counts, cmap=S.sequential_cmap(), aspect="auto")
    ax.set_xticks(range(len(classes)))
    ax.set_xticklabels(classes, rotation=40, ha="right", fontsize=8)
    ax.set_yticks(range(len(techniques)))
    ax.set_yticklabels(techniques, fontsize=8)
    vmax = counts.max() or 1
    for i in range(len(techniques)):
        for j in range(len(classes)):
            v = int(counts[i, j])
            if v:
                ax.text(j, i, v, ha="center", va="center", fontsize=7.5,
                        color="white" if counts[i, j] > 0.6 * vmax else S.INK)
    ax.set_xlabel("Vulnerability class (ground truth)")
    S.title_block(ax, "Attack technique × vulnerability outcome",
                  "New unique findings, all profiles pooled")
    ax.grid(False)
    fig.colorbar(im, ax=ax, fraction=0.025, pad=0.02, label="findings")
    S.savefig(fig, out / "fig8_technique_outcome_heatmap.png")


# ---------------------------------------------------------------------------
# Defense figures (exp3)
# ---------------------------------------------------------------------------


def fig_defense_effectiveness(results_dir: Path, out: Path) -> dict:
    p = results_dir / "exp3_defenses" / "defense_results.json"
    if not p.exists():
        return {}
    data = json.loads(p.read_text())
    base = np.array(data["baseline"], float)
    base_mean = base.mean()
    summary = {"baseline_mean": round(base_mean, 2), "single": {}, "cumulative": {}}

    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12.4, 5.2),
                                   gridspec_kw={"width_ratios": [1, 1.15]})

    # -- single layer reduction ----------------------------------------
    singles = data["single"]
    layers = list(singles.keys())
    reductions, errs = [], []
    for layer in layers:
        vals = np.array(singles[layer], float)
        red = (base_mean - vals.mean()) / base_mean * 100 if base_mean else 0
        reductions.append(red)
        _, lo, hi = M.bootstrap_ci((base_mean - vals) / base_mean * 100)
        errs.append((red - lo, hi - red))
        summary["single"][layer] = {"mean_findings": round(vals.mean(), 2),
                                    "reduction_pct": round(red, 1)}
    order = np.argsort(reductions)
    layers = [layers[i] for i in order]
    reductions = [reductions[i] for i in order]
    errs = np.array([errs[i] for i in order]).T
    y = np.arange(len(layers))
    grad = S.sequential_cmap()(np.linspace(0.35, 0.95, len(layers)))
    ax1.barh(y, reductions, color=grad, edgecolor=S.SURFACE, xerr=errs,
             error_kw={"elinewidth": 1, "capsize": 2.5, "ecolor": S.INK2}, zorder=3)
    for yi, red in zip(y, reductions):
        ax1.text(red + 1.2, yi, f"{red:.0f}%", va="center", fontsize=8.4,
                 color=S.INK2, fontweight="bold")
    ax1.set_yticks(y); ax1.set_yticklabels(layers, fontsize=8.8)
    ax1.set_xlabel("Attack-success reduction vs. undefended (%)")
    S.title_block(ax1, "Single defense layers", "Each control alone, on the naïve base agent")

    # -- cumulative stacking -------------------------------------------
    cum = data["cumulative"]
    labels = list(cum.keys())
    means = [np.mean(cum[k]) for k in labels]
    xs = np.arange(len(means) + 1)
    ys = [base_mean] + means
    ax2.plot(xs, ys, color=S.BLUE, linewidth=2.2, marker="o", markersize=7,
             markeredgecolor=S.SURFACE, zorder=3)
    ax2.fill_between(xs, ys, base_mean, color=S.BLUE, alpha=0.08, linewidth=0)
    tick_labels = ["undefended"] + [f"+{k.split('+')[-1]}" for k in labels]
    ax2.set_xticks(xs)
    ax2.set_xticklabels(tick_labels, rotation=35, ha="right", fontsize=8)
    for x_, yv in zip(xs, ys):
        ax2.text(x_, yv + 0.25, f"{yv:.1f}", ha="center", fontsize=8, color=S.INK2)
    ax2.set_ylabel("Mean unique findings (residual risk)")
    S.title_block(ax2, "Cumulative defense-in-depth",
                  "Layers added in deployment order · lower = safer")
    ax2.margins(x=0.03, y=0.15)
    for i, k in enumerate(labels):
        summary["cumulative"][k] = round(float(np.mean(cum[k])), 2)
    S.savefig(fig, out / "fig9_defense_effectiveness.png")
    return summary


# ---------------------------------------------------------------------------
# Ablation figure (exp4)
# ---------------------------------------------------------------------------


def _abl_metric(cell, key):
    """Backward/forward compatible accessor: cell is either a list (old schema)
    or a dict {findings, yardstick_coverage} (current schema)."""
    if isinstance(cell, dict):
        return np.array(cell.get(key, []), float)
    return np.array(cell, float)  # legacy: list of findings


def fig_dimension_ablation(results_dir: Path, out: Path) -> dict:
    p = results_dir / "exp4_ablation" / "ablation_results.json"
    if not p.exists():
        return {}
    data = json.loads(p.read_text())
    profiles = list(next(iter(data.values())).keys())

    labels = [k for k in data if k != "all"]
    order = ["none", "action_only"] + [k for k in labels if k.startswith("no_")]
    labels = [k for k in order if k in data]
    all_labels = ["all"] + labels

    # Primary metric: fraction of the FULL behavioural space explored (yardstick).
    full_cov = {pr: _abl_metric(data["all"][pr], "yardstick_coverage").mean()
                for pr in profiles}
    fig, ax = plt.subplots(figsize=(10.2, 5.2))
    x = np.arange(len(all_labels))
    width = 0.8 / len(profiles)
    summary = {"metric": "yardstick_coverage_and_findings"}

    for i, prof in enumerate(profiles):
        covs, errs = [], []
        for k in all_labels:
            c = _abl_metric(data[k][prof], "yardstick_coverage")
            m = c.mean() / full_cov[prof] * 100 if full_cov[prof] else 0
            covs.append(m)
            _, lo, hi = M.bootstrap_ci(c / full_cov[prof] * 100) if full_cov[prof] else (m, m, m)
            errs.append((m - lo, hi - m))
        off = (i - (len(profiles) - 1) / 2) * width
        errs = np.array(errs).T
        ax.bar(x + off, covs, width * 0.9, yerr=errs,
               color=S.PROFILE_COLORS.get(prof, S.BLUE), label=prof,
               edgecolor=S.SURFACE, linewidth=0.6,
               error_kw={"elinewidth": 0.9, "capsize": 2, "ecolor": S.INK2}, zorder=3)
        summary[prof] = {k: {
            "yardstick_cov": round(float(_abl_metric(data[k][prof], "yardstick_coverage").mean()), 1),
            "findings": round(float(_abl_metric(data[k][prof], "findings").mean()), 2),
        } for k in all_labels}

    ax.axhline(100, color=S.INK2, linewidth=1.0, linestyle=(0, (4, 3)))
    ax.text(len(all_labels) - 0.5, 100.5, "full coverage = 100%", ha="right",
            va="bottom", fontsize=8, color=S.MUTED)
    ax.set_xticks(x)
    nice = {"all": "all five", "none": "none (bug-only)", "action_only": "action only"}
    ax.set_xticklabels([nice.get(k, k.replace("no_", "− ")) for k in all_labels],
                       rotation=30, ha="right", fontsize=8.6)
    ax.set_ylabel("Full behavioural space explored (% of all-dims)")
    ax.set_ylim(0, 108)
    S.title_block(ax, "Coverage-dimension ablation",
                  "Search guided by a subset of dimensions, scored on the full space · "
                  "guiding with fewer dimensions explores less of it")
    ax.legend(title="agent profile", loc="lower left", fontsize=8.8)
    S.savefig(fig, out / "fig10_dimension_ablation.png")
    return summary


# ---------------------------------------------------------------------------
# Guardrail state distribution
# ---------------------------------------------------------------------------


def fig_guardrail_distribution(records, out: Path) -> None:
    from boundsec.core.types import ResponseMode
    modes = [m.value for m in ResponseMode]
    mode_color = {
        "hard_refusal": S.GREEN, "soft_refusal": "#69b34c", "deflection": S.AQUA,
        "clarification": S.YELLOW, "partial_compliance": S.ORANGE,
        "meta_disclosure": S.MAGENTA, "full_compliance": S.RED,
        "transport_error": S.GREY,
    }
    strategies = [s for s in S.STRATEGY_ORDER if any(r.strategy == s for r in records)]
    profile = "hardened" if any(r.profile == "hardened" for r in records) else records[0].profile
    counts = {s: Counter() for s in strategies}
    for r in records:
        if r.profile != profile:
            continue
        if r.strategy in counts:
            for row in r.rows:
                counts[r.strategy][row["response_mode"]] += 1

    fig, ax = plt.subplots(figsize=(9.0, 4.6))
    present = [m for m in modes if any(counts[s].get(m, 0) for s in strategies)]
    y = np.arange(len(strategies))
    left = np.zeros(len(strategies))
    for m in present:
        vals = np.array([counts[s].get(m, 0) for s in strategies], float)
        totals = np.array([sum(counts[s].values()) or 1 for s in strategies])
        frac = vals / totals * 100
        ax.barh(y, frac, left=left, color=mode_color.get(m, S.GREY),
                edgecolor=S.SURFACE, linewidth=1.2, label=m, zorder=3)
        left += frac
    ax.set_yticks(y); ax.set_yticklabels([S.strat_label(s) for s in strategies], fontsize=9)
    ax.set_xlabel("Share of queries (%)")
    ax.set_xlim(0, 100)
    S.title_block(ax, "Guardrail response regime reached, by strategy",
                  f"Agent profile: {profile} · guided search drives the agent toward compliance")
    ax.legend(loc="upper center", bbox_to_anchor=(0.5, -0.13), ncol=4, fontsize=8)
    ax.grid(False)
    S.savefig(fig, out / "fig11_guardrail_distribution.png")


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------


def generate_all(results_dir: Path, figures_dir: Path) -> dict:
    results_dir, figures_dir = Path(results_dir), Path(figures_dir)
    figures_dir.mkdir(parents=True, exist_ok=True)
    summary: dict = {}

    # methodology diagrams (data-independent)
    from boundsec.analysis.diagrams import generate_diagrams
    generate_diagrams(figures_dir)

    exp1 = results_dir / "exp1_strategy"
    if exp1.exists():
        records = load_all(exp1)
        summary["strategy"] = fig_strategy_bars(records, figures_dir)
        fig_discovery_curves(records, figures_dir)
        fig_coverage_growth(records, figures_dir)
        summary["effect_sizes"] = fig_effect_sizes(records, figures_dir)
        fig_operator_effectiveness(records, figures_dir)
        fig_technique_outcome_heatmap(records, figures_dir)
        fig_guardrail_distribution(records, figures_dir)

    summary["detectors"] = fig_detector_roc_pr(results_dir, figures_dir)
    fig_detector_calibration(results_dir, figures_dir)
    summary["defenses"] = fig_defense_effectiveness(results_dir, figures_dir)
    summary["ablation"] = fig_dimension_ablation(results_dir, figures_dir)

    (figures_dir / "summary.json").write_text(json.dumps(summary, indent=2))
    (results_dir / "summary.json").write_text(json.dumps(summary, indent=2))
    return summary


if __name__ == "__main__":
    import sys
    rd = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("results")
    fd = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("figures")
    generate_all(rd, fd)
    print(f"figures -> {fd}")
