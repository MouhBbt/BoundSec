"""
BoundSec - Methodology diagrams.

Hand-drawn-by-code schematics that explain the *mechanism* of the framework:
the coverage-guided feedback loop and the behavioural-coverage abstraction.
These are rendered with the same style tokens as the data figures so the whole
figure set reads as one system.  They take no data - they document the design.
"""

from __future__ import annotations

from pathlib import Path

import matplotlib.pyplot as plt
from matplotlib.patches import FancyArrowPatch, FancyBboxPatch

from boundsec.analysis import style as S

S.install()


def _box(ax, x, y, w, h, text, color, text_color="white", fontsize=10.5, alpha=1.0):
    box = FancyBboxPatch((x, y), w, h, boxstyle="round,pad=0.02,rounding_size=0.06",
                         linewidth=0, facecolor=color, alpha=alpha, zorder=2)
    ax.add_patch(box)
    ax.text(x + w / 2, y + h / 2, text, ha="center", va="center",
            color=text_color, fontsize=fontsize, fontweight="bold", zorder=3,
            linespacing=1.35)
    return (x + w / 2, y + h / 2, x, y, w, h)


def _arrow(ax, p1, p2, color=S.INK2, style="-|>", rad=0.0, lw=1.8, label=None,
           label_offset=(0, 0.16), ls="-"):
    a = FancyArrowPatch(p1, p2, arrowstyle=style, mutation_scale=16,
                        connectionstyle=f"arc3,rad={rad}", color=color,
                        linewidth=lw, zorder=1, linestyle=ls)
    ax.add_patch(a)
    if label:
        mx, my = (p1[0] + p2[0]) / 2, (p1[1] + p2[1]) / 2
        ax.text(mx + label_offset[0], my + label_offset[1], label, ha="center",
                va="center", fontsize=8.6, color=color, style="italic", zorder=4)


def diagram_feedback_loop(out: Path) -> None:
    """The coverage-guided evolutionary loop that is the core contribution."""
    fig, ax = plt.subplots(figsize=(11.5, 6.4))
    ax.set_xlim(0, 12); ax.set_ylim(0, 7); ax.axis("off")

    corpus = _box(ax, 0.4, 3.0, 2.1, 1.4,
                  "Seed corpus\n+ evolved\ninputs", S.VIOLET, fontsize=10)
    sched = _box(ax, 3.2, 4.6, 2.3, 1.2,
                 "Power schedule\n(pick seed)", S.BLUE, fontsize=9.6)
    bandit = _box(ax, 3.2, 1.6, 2.3, 1.2,
                  "Operator bandit\n(pick mutation)", S.BLUE, fontsize=9.6)
    mutate = _box(ax, 6.2, 3.0, 1.9, 1.4,
                  "Mutate →\nFuzzCase", S.AQUA, fontsize=10)
    target = _box(ax, 8.7, 4.5, 2.7, 1.3,
                  "Target agent\n(gym / live LLM)", S.ORANGE, fontsize=9.8)
    cov = _box(ax, 8.7, 2.55, 2.7, 1.1,
               "Behavioural\ncoverage map", "#1b539a", fontsize=9.6)
    oracle = _box(ax, 8.7, 0.7, 2.7, 1.1,
                  "Detector\n(oracle)", S.MAGENTA, fontsize=9.8)

    # forward path
    _arrow(ax, (2.5, 3.9), (3.2, 5.0), rad=0.15)
    _arrow(ax, (2.5, 3.5), (3.2, 2.4), rad=-0.15)
    _arrow(ax, (5.5, 5.1), (6.55, 4.3), rad=0.1)
    _arrow(ax, (5.5, 2.3), (6.55, 3.1), rad=-0.1)
    _arrow(ax, (8.1, 3.9), (8.7, 4.65), rad=0.12, label="prompt", label_offset=(-0.42, 0.05))
    _arrow(ax, (10.05, 4.5), (10.05, 3.68), label="trace", label_offset=(0.5, 0))
    _arrow(ax, (10.05, 2.55), (10.05, 1.82), label="score", label_offset=(0.55, 0))

    # feedback path (the greybox signal) — routed along the bottom to avoid boxes
    _arrow(ax, (9.4, 2.55), (1.45, 3.0), color=S.BLUE, rad=-0.52, lw=2.2)
    ax.text(6.0, 0.62, "new coverage  →  keep input  &  reward operator",
            ha="center", va="center", fontsize=9.2, color=S.BLUE,
            style="italic", fontweight="bold", zorder=5)
    _arrow(ax, (8.7, 0.95), (2.5, 3.0), color=S.MAGENTA, rad=-0.18, lw=1.7, ls=(0, (5, 3)))
    ax.text(5.4, 1.5, "bug → unique finding", ha="center", va="center",
            fontsize=8.6, color=S.MAGENTA, style="italic", zorder=5)

    ax.text(0.4, 6.62, "The coverage-guided feedback loop",
            fontsize=15, fontweight="bold", color=S.INK)
    ax.text(0.4, 6.17,
            "Inputs that light up new agent behaviour are kept and mutated further; "
            "the operator bandit is rewarded for coverage, compliance-gradient and bugs.",
            fontsize=9.8, color=S.MUTED)
    S.savefig(fig, out / "fig0_feedback_loop.png")


def diagram_coverage_abstraction(out: Path) -> None:
    """How one agent trace projects onto the five behavioural coverage dimensions."""
    fig, ax = plt.subplots(figsize=(11.5, 6.2))
    ax.set_xlim(0, 12); ax.set_ylim(0, 7); ax.axis("off")

    _box(ax, 0.3, 2.6, 2.7, 2.0,
         "Agent trace\n\n• tool calls\n• responses\n• status/latency",
         S.VIOLET, fontsize=9.4)

    dims = [
        ("Action", "A:tool|arg-class|outcome", "basic blocks", S.BLUE, 5.05),
        ("Transition", "T:tool_i → tool_j", "edges/branches", "#1b539a", 4.05),
        ("Guardrail", "G:response-mode@turn", "state machine", S.AQUA, 3.05),
        ("Fault", "E:status|error-class", "crash buckets", S.ORANGE, 2.05),
        ("Novelty", "N:simhash-bucket", "output diversity", S.MAGENTA, 1.05),
    ]
    for name, form, analogue, color, y in dims:
        _box(ax, 3.7, y, 3.7, 0.82, "", color, fontsize=9)
        ax.text(3.85, y + 0.41, name, ha="left", va="center", color="white",
                fontsize=9.6, fontweight="bold")
        ax.text(7.25, y + 0.41, form, ha="right", va="center", color="white",
                fontsize=8.3, family="monospace")
        ax.text(7.6, y + 0.41, f"≈ {analogue}", ha="left", va="center",
                color=S.MUTED, fontsize=8.2, style="italic")
        _arrow(ax, (3.0, 3.6), (3.7, y + 0.41), color=color, rad=0.0, lw=1.3)

    _box(ax, 9.9, 2.6, 1.8, 2.0, "AFL-style\nbitmap\n(2¹⁶ slots)",
         S.INK, fontsize=9.4)
    for _, _, _, color, y in dims:
        _arrow(ax, (7.4, y + 0.41), (9.9, 3.6), color=color, rad=0.05, lw=1.2)

    ax.text(0.3, 6.55, "Behavioural coverage: projecting an agent trace to a bitmap",
            fontsize=14.5, fontweight="bold", color=S.INK)
    ax.text(0.3, 6.12,
            "Unbounded tool arguments are abstracted to a closed set of security-relevant "
            "classes, keeping the coverage domain finite.",
            fontsize=9.6, color=S.MUTED)
    S.savefig(fig, out / "fig0_coverage_abstraction.png")


def generate_diagrams(out: Path) -> None:
    out = Path(out)
    out.mkdir(parents=True, exist_ok=True)
    diagram_feedback_loop(out)
    diagram_coverage_abstraction(out)


if __name__ == "__main__":
    import sys
    generate_diagrams(Path(sys.argv[1]) if len(sys.argv) > 1 else Path("figures"))
    print("diagrams written")
