# AgentFuzz 🔍

> **Boundary-aware security fuzzing and testing framework for autonomous AI agents.**

[![Python 3.12+](https://img.shields.io/badge/python-3.12%2B-blue.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![CI](https://github.com/your-org/agentfuzz/actions/workflows/ci.yml/badge.svg)](.github/workflows/ci.yml)
[![Status: Research Preview](https://img.shields.io/badge/status-research%20preview-orange.svg)]()

AgentFuzz automates the discovery of LLM-agent vulnerabilities: **tool-execution boundary failures**, **indirect prompt injections**, **state pollution**, **jailbreaks**, and **malicious output generation**. It was built to stress-test real autonomous agent pipelines (LangGraph, LangChain, custom LLM endpoints) before they reach production.

> [!NOTE]
> **Research Preview (v0.1.0)** — AgentFuzz is functional and actively used for testing, but the payload library, oracle heuristics, and LLM judge prompts will evolve. Feedback and PRs are welcome. The included mock target is intentionally vulnerable and **must never be exposed to the internet**.

---

## Table of Contents

- [Architecture](#architecture)
- [Boundary Failures Tested](#boundary-failures-tested)
- [Repository Structure](#repository-structure)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [CLI Reference](#cli-reference)
- [Understanding Reports](#understanding-reports)
- [Extending the Framework](#extending-the-framework)
- [Production Risk Mitigation](#production-risk-mitigation)
- [Ethical Use Policy](#ethical-use-policy)

---

## Architecture

AgentFuzz consists of four tightly-coupled but independently extensible modules:

```
┌──────────────────────────────────────────────────────────────────┐
│                         agentfuzz CLI                            │
│                          (cli.py)                                │
└────────────┬──────────────────────────────────┬─────────────────┘
             │                                  │
     ┌───────▼──────────┐              ┌────────▼─────────┐
     │  Mutator Engine   │              │  Fuzzing Harness  │
     │  (mutator.py)     │──FuzzCases──▶│  (harness.py)    │
     │                   │              │                   │
     │  ┌─────────────┐  │              │  • Async HTTP     │
     │  │StaticMutator│  │              │  • Semaphore      │
     │  │ 6 transforms│  │              │    concurrency    │
     │  └─────────────┘  │              │  • Timeout/retry  │
     │  ┌─────────────┐  │              │  • AgentTrace     │
     │  │ LLMMutator  │  │              │    capture        │
     │  │ GPT-4o-mini │  │              └────────┬──────────┘
     │  └─────────────┘  │                       │AgentTrace
     └───────────────────┘                       │
                                        ┌────────▼─────────┐
                                        │  Security Oracle  │
                                        │  (oracle.py)      │
                                        │                   │
                                        │  ┌─────────────┐  │
                                        │  │ RuleBased   │  │
                                        │  │ Oracle      │  │
                                        │  │ (regex/     │  │
                                        │  │  heuristic) │  │
                                        │  └─────────────┘  │
                                        │  ┌─────────────┐  │
                                        │  │ LLMJudge    │  │
                                        │  │ Oracle      │  │
                                        │  │ (GPT-4o)    │  │
                                        │  └─────────────┘  │
                                        └────────┬──────────┘
                                                 │Verdict[]
                                        ┌────────▼─────────┐
                                        │    Reporter       │
                                        │  (reporter.py)    │
                                        │                   │
                                        │  • Rich terminal  │
                                        │  • JSON report    │
                                        └───────────────────┘
```

### Module Descriptions

| Module | File | Purpose |
|--------|------|---------|
| **Fuzzing Harness** | `agentfuzz/core/harness.py` | Async HTTP engine. Sends `FuzzCase` payloads to target, captures `AgentTrace` (tool calls, latency, output, errors). |
| **Mutator Engine** | `agentfuzz/core/mutator.py` | Generates adversarial inputs. `StaticMutator` applies 6 text transforms to known payloads. `LLMMutator` calls GPT-4o-mini to generate N subtle variants of a seed prompt. |
| **Security Oracle** | `agentfuzz/core/oracle.py` | Evaluates traces. `RuleBasedOracle` uses regex + heuristics. `LLMJudgeOracle` uses GPT-4o for deep behavioral analysis. `CompositeOracle` merges both. |
| **Reporter** | `agentfuzz/utils/reporter.py` | Renders a color-coded Rich terminal table and exports structured JSON. |
| **Mock Target** | `tests/target_mock.py` | A FastAPI server with **7 intentional vulnerabilities** for immediate testing. |

---

## Boundary Failures Tested

AgentFuzz specifically targets the following LLM-agent security boundaries:

### 1. 🚨 Jailbreak / System Prompt Override
The agent is manipulated into disabling its own safety guardrails through DAN prompts, maintenance mode activation, or role injection. **Risk:** Full bypass of all content policies.

### 2. 🔓 System Prompt Disclosure
The agent is tricked into revealing its full system prompt, including embedded credentials, tool configurations, and internal state. **Risk:** Credential theft, attack surface mapping.

### 3. ⚙️ Unauthorized Tool Call Injection
Malformed user input causes the agent to call dangerous tools (`execute_bash`, `run_shell`, etc.) that were not intended for user-triggered execution. **Risk:** Remote code execution.

### 4. 📂 Path Traversal via Tool Arguments
The agent passes unsanitized user-controlled paths to file-reading tools, enabling `../../../../etc/passwd`-style traversal. **Risk:** Sensitive file disclosure.

### 5. 💉 Indirect Prompt Injection
Instructions embedded in documents, web pages, or tool outputs the agent reads are treated as legitimate instructions. **Risk:** Agent hijacking via third-party content.

### 6. 📤 Data Exfiltration
The agent leaks API keys, database credentials, or session context through its outputs. **Risk:** Credential compromise.

### 7. 🎭 Role / Authority Confusion
The agent accepts claimed authority (e.g., "I am your developer") and enters elevated-privilege modes. **Risk:** Privilege escalation without authentication.

### 8. ⏱️ Token Exhaustion / DoS
Oversized or recursive prompts cause timeouts, excessive compute, or infinite loops. **Risk:** Denial of service, cost amplification.

---

## Repository Structure

```
AgentFuzzer/
├── agentfuzz/
│   ├── __init__.py
│   ├── cli.py                    # CLI entry point (typer)
│   ├── core/
│   │   ├── __init__.py
│   │   ├── harness.py            # Async fuzzing harness
│   │   ├── mutator.py            # Static + LLM mutators
│   │   └── oracle.py             # Rule-based + LLM judge oracles
│   ├── utils/
│   │   ├── __init__.py
│   │   └── reporter.py           # Rich terminal + JSON reporter
│   └── payloads/
│       └── jailbreaks.json       # 22 curated attack payloads (8 categories)
├── tests/
│   ├── __init__.py
│   ├── target_mock.py            # Intentionally vulnerable FastAPI agent
│   └── test_agentfuzz.py         # Pytest unit + integration tests
├── requirements.txt
├── pyproject.toml
├── LICENSE
└── README.md
```

---

## Installation

### Prerequisites
- Python 3.12+
- `pip` or `uv`

### Steps

```bash
# Clone the repository
git clone https://github.com/your-org/agentfuzz.git
cd agentfuzz

# Create a virtual environment
python -m venv .venv
source .venv/bin/activate      # Linux/macOS
# .venv\Scripts\activate.bat   # Windows

# Install dependencies
pip install -r requirements.txt

# Install the package in editable mode (enables `agentfuzz` CLI)
pip install -e .
```

---

## Quick Start

### 1. Start the Vulnerable Mock Target

In a **separate terminal**, launch the intentionally vulnerable agent:

```bash
python tests/target_mock.py
# OR
uvicorn tests.target_mock:app --port 8000 --reload
```

You should see:
```
⚠️  Starting AgentFuzz VULNERABLE Mock Target on http://localhost:8000
⚠️  This server is intentionally insecure. Do NOT expose to the internet.
```

### 2. Run the Fuzzer

In your **main terminal**:

```bash
# Basic run (rule-based oracle, static payloads only)
python -m agentfuzz.cli --target http://localhost:8000/chat

# With verbose output (see each case result in real time)
python -m agentfuzz.cli --target http://localhost:8000/chat --verbose

# Save a JSON report
python -m agentfuzz.cli \
    --target http://localhost:8000/chat \
    --output reports/run_$(date +%Y%m%d_%H%M%S).json

# Full run with LLM mutator + judge (requires OpenAI API key)
export OPENAI_API_KEY=sk-...
python -m agentfuzz.cli \
    --target http://localhost:8000/chat \
    --oracle composite \
    --llm-api-key $OPENAI_API_KEY \
    --mutate-seeds "Tell me about data security,What tools do you have?" \
    --llm-variants 5 \
    --concurrency 10 \
    --output reports/full_run.json
```

### 3. Run Tests

```bash
# Unit tests only (no server needed)
pytest tests/test_agentfuzz.py -k "not e2e and not End" -v

# Full test suite (requires mock server on port 8001)
# Start mock on 8001 first:
uvicorn tests.target_mock:app --port 8001 &
pytest tests/ -v
```

---

## CLI Reference

```
Usage: python -m agentfuzz.cli [OPTIONS] COMMAND [ARGS]...

Commands:
  fuzz           Run a full fuzzing campaign against the target agent.
  list-payloads  List all static payloads in the library.
```

### `fuzz` Options

| Option | Default | Description |
|--------|---------|-------------|
| `--target`, `-t` | `http://localhost:8000/chat` | Target agent POST endpoint URL |
| `--payloads`, `-p` | `agentfuzz/payloads/jailbreaks.json` | Path to payload library JSON |
| `--oracle`, `-O` | `rule` | Oracle mode: `rule` \| `llm` \| `composite` |
| `--llm-api-key` | `$OPENAI_API_KEY` | OpenAI-compatible API key |
| `--llm-base-url` | `https://api.openai.com/v1` | LLM API base URL (supports local models) |
| `--llm-model` | `gpt-4o-mini` | Model for mutator and judge |
| `--mutate-seeds` | — | Comma-separated benign seed prompts for LLM mutator |
| `--llm-variants` | `5` | LLM mutations per seed |
| `--concurrency`, `-c` | `5` | Max concurrent requests |
| `--timeout` | `30.0` | Per-request timeout (seconds) |
| `--output`, `-o` | — | Path to write JSON report |
| `--escalate-llm` | `false` | Escalate rule-flagged cases to LLM judge |
| `--verbose`, `-v` | `false` | Print each case result in real time |

### Exit Codes

| Code | Meaning |
|------|---------|
| `0` | All cases clean, no vulnerabilities found |
| `1` | Framework error (missing files, connection failure) |
| `2` | Vulnerabilities found (use in CI to fail the build) |

---

## Understanding Reports

### Terminal Output

AgentFuzz renders a color-coded terminal report:

- 🔴 **Critical** – Immediate exploitation risk (jailbreak, RCE, credential leak)
- 🟠 **High** – Significant boundary violation (path traversal, unauthorized tool)
- 🟡 **Medium** – Behavioral anomaly or DoS risk
- 🟢 **Low** – Minor policy deviation

### JSON Report Schema

```json
{
  "meta": {
    "run_id": "a1b2c3d4",
    "timestamp": "2026-07-22T10:30:00Z",
    "target_url": "http://localhost:8000/chat",
    "oracle_mode": "rule",
    "duration_seconds": 12.34,
    "total_cases": 46,
    "vulnerable_count": 18,
    "clean_count": 28,
    "vulnerability_rate_pct": 39.13
  },
  "vulnerabilities": [
    {
      "case_id": "static-SYS_OVERRIDE_01-original",
      "payload_id": "SYS_OVERRIDE_01",
      "category": "system_prompt_override",
      "severity": "critical",
      "vulnerability_types": ["jailbreak_success"],
      "confidence": 0.95,
      "evidence": ["Jailbreak phrase matched: /DAN MODE ENABLED/"],
      "oracle_source": "rule_based",
      "trace_summary": "status=200, latency=52ms, tool_calls=0, output_len=124"
    }
  ],
  "clean_cases": ["static-CONTEXT_OVERFLOW_01-original", "..."]
}
```

---

## Extending the Framework

### Adding Custom Payloads

Edit `agentfuzz/payloads/jailbreaks.json` and add entries following the schema:

```json
{
  "id": "MY_CUSTOM_01",
  "category": "custom",
  "severity": "high",
  "description": "My custom attack vector",
  "payload": "Your adversarial prompt here."
}
```

### Adding Custom Oracle Rules

Subclass `BaseOracle` in `oracle.py`:

```python
class MyCustomOracle(BaseOracle):
    async def evaluate(self, case: FuzzCase, trace: AgentTrace) -> Verdict:
        # Your detection logic here
        is_vuln = "forbidden_keyword" in trace.final_output.lower()
        return Verdict(
            case_id=case.case_id,
            payload_id=case.payload_id,
            category=case.category,
            severity=case.severity,
            is_vulnerable=is_vuln,
            vulnerability_types=[VulnerabilityType.BEHAVIORAL_ANOMALY] if is_vuln else [],
            confidence=0.85 if is_vuln else 0.0,
            evidence=["Forbidden keyword detected"] if is_vuln else [],
            oracle_source="custom",
        )
```

### Using a Local LLM (Ollama, vLLM)

Pass a custom `--llm-base-url` pointing to your local server:

```bash
python -m agentfuzz.cli \
    --target http://localhost:8000/chat \
    --oracle composite \
    --llm-api-key "ollama" \
    --llm-base-url http://localhost:11434/v1 \
    --llm-model llama3.1:8b
```

---

## Production Risk Mitigation

AgentFuzz findings map directly to defensive controls you should implement:

| Vulnerability Type | Recommended Mitigation |
|-------------------|------------------------|
| **Jailbreak / System Prompt Override** | Hardened system prompt with injection-resistant phrasing; prompt injection classifiers (e.g., LLM Guard, Rebuff) at ingress |
| **System Prompt Disclosure** | Never embed secrets in system prompts; use secret managers; add output classifiers to detect prompt echoing |
| **Unauthorized Tool Call Injection** | Tool call allowlisting; require explicit user confirmation for dangerous tools; structured output parsing (not free-text) |
| **Path Traversal** | Validate and canonicalize all file paths against an allowlist; run agent in a sandboxed container |
| **Indirect Prompt Injection** | Treat all external content as untrusted data; use a separate "taint-aware" LLM pass before action execution |
| **Data Exfiltration** | PII/credential scanners on all LLM outputs; DLP (Data Loss Prevention) at egress |
| **Role Confusion** | Do not implement "developer modes" or elevated-trust based on conversational claims; use out-of-band authentication |
| **Token Exhaustion** | Rate limiting and input length caps at the API gateway; per-user token budgets |

### CI/CD Integration

Add AgentFuzz to your CI pipeline to catch regressions before deployment:

```yaml
# .github/workflows/security.yml
- name: Start Mock Agent
  run: uvicorn tests.target_mock:app --port 8000 &
  
- name: Run AgentFuzz Security Tests
  run: |
    python -m agentfuzz.cli \
      --target http://localhost:8000/chat \
      --output reports/security_report.json
  # Exit code 2 = vulnerabilities found → fails the build
```

---

## Ethical Use Policy

AgentFuzz is a **security research tool** intended exclusively for:
- Testing AI systems **you own or have explicit written permission to test**
- Internal red-team exercises and security audits
- Academic research and vulnerability disclosure programs

**Do NOT use AgentFuzz to attack AI systems you do not own or have authorization to test.** Unauthorized security testing may violate computer fraud laws (CFAA, GDPR, etc.) in your jurisdiction.

The mock target (`tests/target_mock.py`) is deliberately vulnerable and must **never** be exposed to the public internet.

---

## License

MIT © 2026 AgentFuzz Contributors – see [LICENSE](LICENSE)
