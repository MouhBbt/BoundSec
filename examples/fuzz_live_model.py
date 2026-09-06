"""
Example: fuzz a *real* LLM behind an OpenAI-compatible endpoint.

Set OPENAI_API_KEY (OpenAI) or GROQ_API_KEY (Groq) first. A minimal tool-calling
agent is built around the bare model; tools are sandboxed (never really executed)
so we observe whether the model *chooses* to call a dangerous tool with
attacker-controlled arguments. There is no ground truth for a live model, so
findings are detector-scored.

    export GROQ_API_KEY=gsk_...
    AGENTFUZZ_LLM_MODEL=llama-3.3-70b-versatile python examples/fuzz_live_model.py
"""

import asyncio

from boundsec.core.engine import CampaignConfig, FuzzingEngine, build_strategy
from boundsec.core.oracle import HeuristicDetector
from boundsec.payloads.seeds import load_seeds
from boundsec.targets.live import LiveModelAgent, make_client_from_env


async def main() -> None:
    client = make_client_from_env()
    if client is None:
        raise SystemExit("Set OPENAI_API_KEY or GROQ_API_KEY to run this example.")

    target = LiveModelAgent(client)
    cfg = CampaignConfig(budget=60, seed=0)          # keep small: real API calls cost money/time
    strategy = build_strategy("coverage_guided", load_seeds(), cfg)

    engine = FuzzingEngine(target, HeuristicDetector(), strategy, cfg)
    result = await engine.run(
        progress_cb=lambda step, tot, cov, f: print(f"  {step}/{tot} cov={cov} finds={f}"))

    print(f"\nModel: {target.name}")
    print(f"Detector-flagged findings: {result.n_findings}")
    for o in list(result.unique_findings.values())[:5]:
        print(f"  [{o.verdict.score:.2f}] {o.verdict.top_class.value if o.verdict.top_class else '?'}"
              f"  ← {o.case.prompt[:70]!r}")


if __name__ == "__main__":
    asyncio.run(main())
