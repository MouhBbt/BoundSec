# Contributing to AgentFuzz

Thank you for your interest in contributing! AgentFuzz is a research tool, and the most impactful
contributions are usually **new attack payloads**, **improved oracle rules**, and **real-world target
adapters**. All are welcome.

---

## Ways to Contribute

| Type | Where | Impact |
|------|-------|--------|
| New attack payloads | `agentfuzz/payloads/jailbreaks.json` | ⭐⭐⭐ High |
| New oracle detection rules | `agentfuzz/core/oracle.py` | ⭐⭐⭐ High |
| Target adapters / example agents | `examples/` | ⭐⭐ Medium |
| Bug reports | GitHub Issues | ⭐⭐ Medium |
| Documentation improvements | `README.md`, docstrings | ⭐ Low |

---

## Development Setup

```bash
git clone https://github.com/your-org/agentfuzz.git
cd agentfuzz

python -m venv .venv
source .venv/bin/activate   # Linux/macOS
# .venv\Scripts\activate    # Windows

pip install -r requirements.txt
pip install -e ".[dev]"     # installs ruff, pytest extras
```

### Run tests

```bash
# Unit tests (no server needed — fast)
make test-unit

# Full suite including integration tests (starts mock target automatically)
make test

# Lint + format check
make lint
```

---

## Adding a Payload

Payloads live in [`agentfuzz/payloads/jailbreaks.json`](agentfuzz/payloads/jailbreaks.json).
Each entry must follow this schema:

```json
{
  "id": "CATEGORY_XX",
  "category": "one_of_the_categories_below",
  "severity": "critical | high | medium | low",
  "description": "One-line human description of what this tests",
  "payload": "The actual adversarial prompt text"
}
```

**Valid categories:**
- `system_prompt_override`
- `tool_call_injection`
- `indirect_prompt_injection`
- `context_overflow`
- `schema_manipulation`
- `data_exfiltration`
- `role_confusion`
- `multi_turn_manipulation`

### Payload Quality Bar

- ✅ The payload should represent a **real attack vector** observed in the wild or in published research.
- ✅ Link to a reference (CVE, paper, blog post) in your PR description if possible.
- ✅ Test it locally against the mock target first: `python -m agentfuzz fuzz --target http://localhost:8000/chat --verbose`
- ❌ Do not add payloads that are purely theoretical with no plausible real-world application.

---

## Adding an Oracle Rule

Oracle rules live in `agentfuzz/core/oracle.py` inside `RuleBasedOracle.evaluate()`.

When adding a new regex pattern:
1. Add the pattern constant near the top of the file with the existing groups (`_JAILBREAK_PHRASES`, etc.)
2. Add a detection block inside `evaluate()` following the existing pattern
3. Add a unit test in `tests/test_agentfuzz.py` under `TestRuleBasedOracle`

```python
# Example: adding a new pattern group
_MY_NEW_PATTERNS = [
    r"(?i)pattern_one",
    r"(?i)pattern_two",
]

# Inside evaluate():
for pattern in _MY_NEW_PATTERNS:
    if re.search(pattern, output, re.IGNORECASE):
        vuln_types.append(VulnerabilityType.BEHAVIORAL_ANOMALY)
        evidence.append(f"My pattern matched: /{pattern}/")
        confidence = max(confidence, 0.80)
        break
```

---

## Pull Request Checklist

Before opening a PR, make sure:

- [ ] `make lint` passes with no errors
- [ ] `make test-unit` passes
- [ ] New payloads have a corresponding note in the PR about what attack vector they test
- [ ] New oracle rules have a corresponding unit test
- [ ] Commit messages are descriptive (not `fix`, `update`, etc.)

---

## Code Style

- **Python 3.12+**, async-first, Pydantic v2 models for all data structures
- **ruff** for linting and formatting (config in `pyproject.toml`)
- **No bare `except:`** — always catch specific exceptions or use `except Exception as exc`
- **No `# TODO` or `# FIXME`** in merged code — open an issue instead

---

## Reporting a Security Issue in AgentFuzz Itself

See [SECURITY.md](SECURITY.md).
