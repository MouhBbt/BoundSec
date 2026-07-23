"""
AgentFuzz – Fuzzing Harness (harness.py)

Asynchronous execution engine that manages interactions with a target agent.
Sends adversarial prompts, captures tool call traces, and logs full outputs.
"""

from __future__ import annotations

import asyncio
import time
import uuid
from typing import Any

import aiohttp
from pydantic import BaseModel, Field

from agentfuzz.utils.reporter import get_console

console = get_console()


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

class ToolCall(BaseModel):
    """Represents a single tool invocation recorded in the agent trace."""
    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    result: str | None = None
    error: str | None = None


class AgentTrace(BaseModel):
    """Full execution trace returned by one agent interaction."""
    trace_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    prompt: str
    raw_response: str = ""
    tool_calls: list[ToolCall] = Field(default_factory=list)
    final_output: str = ""
    latency_ms: float = 0.0
    status_code: int = 200
    error: str | None = None


class FuzzCase(BaseModel):
    """A single fuzz test case with metadata."""
    case_id: str
    payload_id: str
    category: str
    severity: str
    description: str
    prompt: str
    source: str  # "static" | "llm_mutated"


# ---------------------------------------------------------------------------
# Harness
# ---------------------------------------------------------------------------

class FuzzingHarness:
    """
    Asynchronous harness for interacting with a target agent endpoint.

    The harness communicates over HTTP (POST) by default, expecting the target
    to expose a JSON API compatible with the mock target format:

        POST /chat
        Body: {"message": "<prompt>"}
        Response: {
            "response": "<final answer>",
            "tool_calls": [...],   # optional
            "chain_of_thought": "<cot_text>"  # optional
        }
    """

    def __init__(
        self,
        target_url: str,
        timeout_seconds: float = 30.0,
        concurrency: int = 5,
        max_retries: int = 2,
        retry_delay_base: float = 1.0,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        self.target_url = target_url.rstrip("/")
        self.timeout_seconds = timeout_seconds
        self.concurrency = concurrency
        self.max_retries = max_retries
        self.retry_delay_base = retry_delay_base
        self.extra_headers = extra_headers or {}
        self._semaphore: asyncio.Semaphore | None = None
        self._session: aiohttp.ClientSession | None = None

    # ------------------------------------------------------------------
    # Session lifecycle
    # ------------------------------------------------------------------

    async def __aenter__(self) -> "FuzzingHarness":
        self._semaphore = asyncio.Semaphore(self.concurrency)
        connector = aiohttp.TCPConnector(limit=self.concurrency * 2)
        timeout = aiohttp.ClientTimeout(total=self.timeout_seconds)
        self._session = aiohttp.ClientSession(
            connector=connector,
            timeout=timeout,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "AgentFuzz/0.1.0",
                **self.extra_headers,
            },
        )
        return self

    async def __aexit__(self, *args: Any) -> None:
        if self._session:
            await self._session.close()

    # ------------------------------------------------------------------
    # Core interaction
    # ------------------------------------------------------------------

    async def send(self, case: FuzzCase) -> AgentTrace:
        """
        Send a single fuzz case to the target and capture the trace.

        Retries up to ``max_retries`` times on transient errors (connection
        failures, HTTP 5xx responses) using exponential backoff.  Timeouts
        and HTTP 4xx errors are **not** retried — they are surfaced as-is.
        """
        assert self._session is not None, "Harness must be used as an async context manager."
        assert self._semaphore is not None

        trace = AgentTrace(
            prompt=case.prompt,
            trace_id=f"{case.case_id}-{uuid.uuid4().hex[:8]}",
        )

        async with self._semaphore:
            last_error: str | None = None
            for attempt in range(self.max_retries + 1):
                if attempt > 0:
                    delay = self.retry_delay_base * (2 ** (attempt - 1))
                    await asyncio.sleep(delay)

                start = time.monotonic()
                try:
                    payload = {"message": case.prompt, "case_id": case.case_id}
                    async with self._session.post(self.target_url, json=payload) as resp:
                        trace.status_code = resp.status
                        trace.latency_ms = (time.monotonic() - start) * 1000

                        # Retry on server errors (5xx), not on client errors (4xx)
                        if resp.status >= 500 and attempt < self.max_retries:
                            last_error = f"HTTP {resp.status} (will retry)"
                            continue

                        if resp.content_type and "json" in resp.content_type:
                            data: dict[str, Any] = await resp.json()
                        else:
                            raw = await resp.text()
                            trace.raw_response = raw
                            trace.final_output = raw
                            trace.error = f"Non-JSON response (status={resp.status})"
                            return trace

                        trace.raw_response = str(data)
                        trace.final_output = data.get("response", "")

                        # Parse tool calls from response if present
                        raw_tool_calls: list[dict[str, Any]] = data.get("tool_calls", [])
                        for tc in raw_tool_calls:
                            trace.tool_calls.append(
                                ToolCall(
                                    tool_name=tc.get("tool", tc.get("name", "unknown")),
                                    arguments=tc.get("args", tc.get("arguments", {})),
                                    result=tc.get("result"),
                                    error=tc.get("error"),
                                )
                            )
                        return trace  # success

                except asyncio.TimeoutError:
                    # Timeouts are not retried — they are meaningful fuzz signals
                    trace.latency_ms = (time.monotonic() - start) * 1000
                    trace.error = f"Timeout after {self.timeout_seconds}s"
                    trace.status_code = 504
                    return trace
                except aiohttp.ClientConnectorError as exc:
                    last_error = f"Connection error: {exc}"
                    trace.status_code = 0
                    if attempt == self.max_retries:
                        trace.latency_ms = (time.monotonic() - start) * 1000
                        trace.error = last_error
                except aiohttp.ClientResponseError as exc:
                    trace.latency_ms = (time.monotonic() - start) * 1000
                    trace.error = f"HTTP error {exc.status}: {exc.message}"
                    trace.status_code = exc.status
                    return trace  # don't retry protocol errors
                except Exception as exc:  # noqa: BLE001
                    trace.latency_ms = (time.monotonic() - start) * 1000
                    trace.error = f"Unexpected error: {type(exc).__name__}: {exc}"
                    trace.status_code = -1
                    return trace  # don't retry unknown errors

        return trace

    # ------------------------------------------------------------------
    # Batch execution
    # ------------------------------------------------------------------

    async def run_all(self, cases: list[FuzzCase]) -> list[tuple[FuzzCase, AgentTrace]]:
        """
        Execute all fuzz cases concurrently (bounded by semaphore).

        Returns a list of (FuzzCase, AgentTrace) pairs in completion order.
        """
        tasks = [self.send(case) for case in cases]
        traces = await asyncio.gather(*tasks, return_exceptions=False)
        return list(zip(cases, traces))
