#!/usr/bin/env python
"""
Reproduce the full BoundSec evaluation and regenerate every figure.

    python experiments/run_full_suite.py --budget 600 --seeds 15

Deterministic: each campaign is seeded by (strategy, profile, seed), so re-running
reproduces every number and figure bit-for-bit.  Writes results/ and figures/.
"""

from __future__ import annotations

import argparse
import asyncio
import time
from pathlib import Path

import matplotlib
matplotlib.use("Agg")

from boundsec.analysis.experiment import ExperimentConfig, run_all
from boundsec.analysis.figures import generate_all


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--budget", type=int, default=600)
    ap.add_argument("--seeds", type=int, default=15)
    ap.add_argument("--out", default="results")
    ap.add_argument("--figures", default="figures")
    args = ap.parse_args()

    t0 = time.monotonic()
    cfg = ExperimentConfig(budget=args.budget, n_seeds=args.seeds,
                           out_dir=Path(args.out), verbose=True)
    asyncio.run(run_all(cfg))
    summary = generate_all(Path(args.out), Path(args.figures))
    dt = time.monotonic() - t0
    print(f"\n==> Suite complete in {dt/60:.1f} min")
    print(f"==> Results:  {args.out}/")
    print(f"==> Figures:  {args.figures}/  ({len(list(Path(args.figures).glob('*.png')))} PNGs)")

    # headline numbers
    strat = summary.get("strategy", {})
    if strat:
        print("\nHeadline (mean unique findings):")
        for key in sorted(strat):
            if key.endswith("/hardened"):
                print(f"  {key:42s} {strat[key]['mean']}")


if __name__ == "__main__":
    main()
