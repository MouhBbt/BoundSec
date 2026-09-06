"""
BoundSec - Target abstraction.

A :class:`Target` is anything the fuzzer can send a :class:`FuzzCase` to and
observe an :class:`AgentTrace` from.  Two families implement it:

* **Gym targets** (``targets/gym.py``) - deterministic, instrumented reference
  agents that emit :class:`GroundTruth`.  They are the measurement instrument:
  because we know exactly which inputs *should* trigger which vulnerability, we
  can compute detector precision/recall and strategy bug-recall against them.

* **Live targets** (``targets/live.py``) - real OpenAI-compatible / Groq /
  local model endpoints wrapped in a minimal tool-calling agent loop.  These
  have no ground truth, so against them the framework reports detector-scored
  findings only.  They exist to show the method transfers off the benchmark.

Keeping both behind one interface means the engine, coverage and oracle code is
identical in the reproducible benchmark and in the live setting.
"""

from __future__ import annotations

import abc

from boundsec.core.types import AgentTrace, FuzzCase


class Target(abc.ABC):
    """A system under test."""

    name: str = "target"

    @abc.abstractmethod
    async def query(self, case: FuzzCase) -> AgentTrace:
        """Execute one (possibly multi-turn) case and return its full trace."""

    async def health(self) -> bool:
        return True

    @property
    def supports_ground_truth(self) -> bool:
        return False

    def describe(self) -> dict[str, object]:
        return {"name": self.name, "ground_truth": self.supports_ground_truth}
