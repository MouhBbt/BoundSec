"""
BoundSec - Figure style.

A single source of truth for the look of every figure, so the whole evaluation
reads as one system.  The palette is the validated colourblind-safe reference
instance from the data-viz method (worst adjacent CVD ΔE 9.2), assigned to
entities by role - never cycled.  Strategy colours follow the natural
baseline->best ordering (muted grey reference -> blue hero), and every bar chart
carries direct value labels, which is what discharges the low-contrast relief
rule for the aqua slot.
"""

from __future__ import annotations

import matplotlib as mpl
import matplotlib.pyplot as plt

# -- validated categorical palette (light surface) --------------------------
BLUE = "#2a78d6"
ORANGE = "#eb6834"
AQUA = "#1baf7a"
YELLOW = "#eda100"
MAGENTA = "#e87ba4"
GREEN = "#008300"
VIOLET = "#4a3aa7"
RED = "#e34948"
GREY = "#8a8a86"

INK = "#0b0b0b"
INK2 = "#52514e"
MUTED = "#9a9a95"
SURFACE = "#fcfcfb"
GRID = "#e6e6e2"

# -- role assignments -------------------------------------------------------

#: Strategy identity (fixed; baseline grey -> hero blue).
STRATEGY_COLORS: dict[str, str] = {
    "static_replay": GREY,
    "random_mutation": ORANGE,
    "guided_no_bandit": AQUA,
    "coverage_guided": BLUE,
}
STRATEGY_LABELS: dict[str, str] = {
    "static_replay": "Static replay",
    "random_mutation": "Random mutation",
    "guided_no_bandit": "Coverage-guided (no bandit)",
    "coverage_guided": "Coverage-guided (full)",
}
STRATEGY_ORDER = ["static_replay", "random_mutation", "guided_no_bandit", "coverage_guided"]

#: Agent-profile identity (naive -> frontier is an ordered ramp of robustness).
PROFILE_COLORS: dict[str, str] = {
    "naive": "#c94f2e", "basic": "#eda100", "hardened": "#1baf7a", "frontier": "#2a78d6",
}
PROFILE_ORDER = ["naive", "basic", "hardened", "frontier"]

DETECTOR_COLORS: dict[str, str] = {
    "heuristic": BLUE, "canary": AQUA, "ensemble": VIOLET, "llm_judge": ORANGE,
}

#: Sequential single-hue blue ramp (magnitude) and blue<->orange diverging pair.
SEQUENTIAL = ["#eef4fc", "#cfe0f5", "#9ec3ea", "#6aa4df", "#3f88d4", "#2a78d6", "#1a4f8f"]


def install() -> None:
    """Apply the BoundSec matplotlib rcParams globally."""
    mpl.rcParams.update({
        "figure.dpi": 130,
        "savefig.dpi": 200,
        "savefig.bbox": "tight",
        "figure.facecolor": SURFACE,
        "axes.facecolor": SURFACE,
        "savefig.facecolor": SURFACE,
        "font.family": "sans-serif",
        "font.sans-serif": ["DejaVu Sans", "Nimbus Sans", "Liberation Sans", "Arial"],
        "font.size": 10.5,
        "axes.titlesize": 12.5,
        "axes.titleweight": "bold",
        "axes.labelsize": 10.5,
        "axes.labelcolor": INK2,
        "axes.edgecolor": "#cfcfca",
        "axes.linewidth": 0.9,
        "axes.grid": True,
        "axes.axisbelow": True,
        "grid.color": GRID,
        "grid.linewidth": 0.8,
        "xtick.color": INK2,
        "ytick.color": INK2,
        "xtick.labelsize": 9.5,
        "ytick.labelsize": 9.5,
        "legend.frameon": False,
        "legend.fontsize": 9.5,
        "axes.titlepad": 12,
        "axes.spines.top": False,
        "axes.spines.right": False,
        "text.color": INK,
    })


def despine(ax, left: bool = True, bottom: bool = True) -> None:
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    if not left:
        ax.spines["left"].set_visible(False)
    if not bottom:
        ax.spines["bottom"].set_visible(False)


def title_block(ax, title: str, subtitle: str | None = None) -> None:
    """Left-aligned title with a muted subtitle sitting clearly below it."""
    if subtitle:
        # Title lifted well clear of the subtitle; subtitle anchored just above
        # the axes with its top edge, so the two never touch across aspect ratios.
        ax.set_title(title, loc="left", pad=28)
        ax.text(0.0, 1.015, subtitle, transform=ax.transAxes, fontsize=9.5,
                color=MUTED, ha="left", va="bottom")
    else:
        ax.set_title(title, loc="left", pad=10)


def strat_color(name: str) -> str:
    return STRATEGY_COLORS.get(name, GREY)


def strat_label(name: str) -> str:
    return STRATEGY_LABELS.get(name, name)


def sequential_cmap():
    from matplotlib.colors import LinearSegmentedColormap
    return LinearSegmentedColormap.from_list("af_seq", ["#f4f8fd", BLUE, "#123a68"])


def diverging_cmap():
    from matplotlib.colors import LinearSegmentedColormap
    return LinearSegmentedColormap.from_list(
        "af_div", [ORANGE, "#f3efe9", BLUE])


def savefig(fig, path, caption: str | None = None) -> None:
    from pathlib import Path
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    if caption:
        fig.text(0.5, -0.02, caption, ha="center", va="top",
                 fontsize=8.5, color=MUTED, wrap=True)
    fig.savefig(path, bbox_inches="tight", facecolor=SURFACE)
    plt.close(fig)
