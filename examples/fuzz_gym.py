"""
Example: run a coverage-guided campaign against the offline Agent Gym.

No API key required. Prints a discovery summary and the operators the bandit
learned to favour. This is the fastest way to see the framework work.

    python examples/fuzz_gym.py
"""

import asyncio

from boundsec.core.engine import CampaignConfig, FuzzingEngine, build_strategy
from boundsec.core.oracle import HeuristicDetector
from boundsec.payloads.seeds import load_seeds
from boundsec.targets.gym import GymAgent


async def main() -> None:
    target = GymAgent("hardened", seed=0)          # try naive | basic | hardened | frontier
    detector = HeuristicDetector()
    cfg = CampaignConfig(budget=400, seed=0)
    strategy = build_strategy("coverage_guided", load_seeds(), cfg)

    engine = FuzzingEngine(target, detector, strategy, cfg)
    result = await engine.run()

    print(f"Target: {target.name}")
    print(f"Unique vulnerabilities: {result.n_findings}")
    print(f"Behavioural coverage:  {result.final_coverage} bitmap slots")
    print(f"Corpus grew to:        {result.corpus_size} inputs\n")

    print("Findings by class:")
    from collections import Counter
    by_class = Counter(o.verdict.top_class.value
                       for o in result.unique_findings.values() if o.verdict.top_class)
    for cls, n in by_class.most_common():
        print(f"  {cls:26s} {n}")

    if result.scheduler_stats:
        print("\nOperators the bandit favoured:")
        for row in result.scheduler_stats[:5]:
            print(f"  {row['operator']:20s} value={row['value']:.3f} "
                  f"pulls={row['pulls']:3d} bugs={row['bugs']}")


if __name__ == "__main__":
    asyncio.run(main())
