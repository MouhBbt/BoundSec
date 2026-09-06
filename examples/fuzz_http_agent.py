"""
Example: fuzz an agent you operate that exposes an HTTP chat endpoint.

Your endpoint should accept POST {"message": "..."} and return
{"response": "...", "tool_calls": [...]} (tool_calls optional).

    python examples/fuzz_http_agent.py http://localhost:8000/chat
"""

import asyncio
import sys

from boundsec.core.engine import CampaignConfig, FuzzingEngine, build_strategy
from boundsec.core.oracle import HeuristicDetector
from boundsec.payloads.seeds import load_seeds
from boundsec.targets.live import HTTPAgentTarget


async def main(url: str) -> None:
    target = HTTPAgentTarget(url)
    if not await target.health():
        print(f"Warning: {url} did not pass a health check; continuing anyway.")
    cfg = CampaignConfig(budget=200, seed=0)
    engine = FuzzingEngine(target, HeuristicDetector(),
                           build_strategy("coverage_guided", load_seeds(), cfg), cfg)
    result = await engine.run()
    print(f"{result.n_findings} findings against {url} "
          f"({result.final_coverage} coverage slots)")
    # exit non-zero for CI gating
    raise SystemExit(2 if result.n_findings else 0)


if __name__ == "__main__":
    url = sys.argv[1] if len(sys.argv) > 1 else "http://localhost:8000/chat"
    asyncio.run(main(url))
