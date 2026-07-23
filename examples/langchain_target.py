"""
examples/langchain_target.py
──────────────────────────────────────────────────────────────────────────────
A minimal FastAPI wrapper around a real LangChain ReAct agent that you can
point AgentFuzz at for authentic red-team testing.

Prerequisites:
    pip install langchain langchain-openai langchain-community

Usage:
    # Set your OpenAI key
    export OPENAI_API_KEY=sk-...

    # Start this target
    uvicorn examples.langchain_target:app --port 8000 --reload

    # Run AgentFuzz against it (in another terminal)
    python -m agentfuzz fuzz \\
        --target http://localhost:8000/chat \\
        --severity critical \\
        --verbose
"""

from __future__ import annotations

import asyncio
import os
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

app = FastAPI(
    title="AgentFuzz – LangChain Target Example",
    description="A real LangChain ReAct agent for security testing.",
    version="0.1.0",
)

# ---------------------------------------------------------------------------
# Lazy agent initialisation (avoids import errors if langchain isn't installed)
# ---------------------------------------------------------------------------

_agent = None


def _get_agent() -> Any:
    global _agent
    if _agent is not None:
        return _agent

    try:
        from langchain.agents import AgentExecutor, create_react_agent
        from langchain.tools import tool
        from langchain_openai import ChatOpenAI
        from langchain import hub
    except ImportError as exc:
        raise RuntimeError(
            "LangChain is not installed. Run: pip install langchain langchain-openai"
        ) from exc

    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY environment variable is required.")

    llm = ChatOpenAI(model="gpt-4o-mini", temperature=0, api_key=api_key)

    @tool
    def read_file(path: str) -> str:
        """Read a file from the local filesystem. Input: file path string."""
        try:
            with open(path, encoding="utf-8", errors="replace") as fh:
                return fh.read(2048)
        except FileNotFoundError:
            return f"File not found: {path}"
        except PermissionError:
            return f"Permission denied: {path}"

    @tool
    def calculator(expression: str) -> str:
        """Evaluate a safe mathematical expression. Input: math expression string."""
        allowed_chars = set("0123456789+-*/()., ")
        if not all(c in allowed_chars for c in expression):
            return "Error: expression contains disallowed characters"
        try:
            result = eval(expression, {"__builtins__": {}})  # noqa: S307
            return str(result)
        except Exception as exc:  # noqa: BLE001
            return f"Calculation error: {exc}"

    tools = [read_file, calculator]
    prompt = hub.pull("hwchase17/react")
    agent = create_react_agent(llm, tools, prompt)
    _agent = AgentExecutor(agent=agent, tools=tools, verbose=False, handle_parsing_errors=True)
    return _agent


# ---------------------------------------------------------------------------
# Request / Response models (AgentFuzz-compatible)
# ---------------------------------------------------------------------------


class ChatRequest(BaseModel):
    message: str
    case_id: str | None = None


class ToolCallRecord(BaseModel):
    tool: str
    args: dict[str, Any] = {}
    result: str | None = None


class ChatResponse(BaseModel):
    response: str
    tool_calls: list[ToolCallRecord] = []
    chain_of_thought: str = ""


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "agent": "LangChain ReAct Target v0.1.0"}


@app.post("/chat", response_model=ChatResponse)
async def chat(req: ChatRequest) -> ChatResponse:
    """Run the LangChain agent with the given message."""
    if not req.message.strip():
        raise HTTPException(status_code=400, detail="message cannot be empty")

    try:
        agent = _get_agent()
    except RuntimeError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    # Run the synchronous LangChain agent in a thread pool
    loop = asyncio.get_event_loop()
    result = await loop.run_in_executor(
        None,
        lambda: agent.invoke({"input": req.message}),
    )

    output = result.get("output", "")
    intermediate = result.get("intermediate_steps", [])

    tool_calls = []
    cot_parts = []
    for action, observation in intermediate:
        tool_calls.append(
            ToolCallRecord(
                tool=action.tool,
                args={"input": action.tool_input},
                result=str(observation)[:500],
            )
        )
        cot_parts.append(f"[{action.tool}({action.tool_input!r})] → {observation!r}")

    return ChatResponse(
        response=output,
        tool_calls=tool_calls,
        chain_of_thought="\n".join(cot_parts),
    )


if __name__ == "__main__":
    import uvicorn  # noqa: PLC0415

    print("Starting LangChain ReAct agent on http://localhost:8000")
    print("Set OPENAI_API_KEY before starting.")
    uvicorn.run(app, host="0.0.0.0", port=8000)  # noqa: S104
