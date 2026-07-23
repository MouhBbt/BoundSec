# Changelog

All notable changes to AgentFuzz are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Planned
- LangChain/LangGraph real-agent example target
- HTML report output (`--output-format html`)
- Multi-turn attack sequences (stateful session fuzzing)
- PyPI package distribution

---

## [0.1.0] – 2026-07-22

### Added
- **Fuzzing Harness** (`agentfuzz/core/harness.py`) — async aiohttp engine with semaphore
  concurrency control, timeout handling, and full `AgentTrace` capture
- **Mutator Engine** (`agentfuzz/core/mutator.py`) — `StaticMutator` with 6 text transforms
  (homoglyph, whitespace padding, ROT-13, case-mixing, HTML comment embedding, truncation);
  `LLMMutator` using any OpenAI-compatible API; `CompositeMutator` combining both
- **Security Oracle** (`agentfuzz/core/oracle.py`) — `RuleBasedOracle` with 8 detection
  categories (jailbreak, system prompt leak, unauthorized tool call, dangerous command exec,
  path traversal, data exfiltration, token exhaustion, schema failures); `LLMJudgeOracle` for
  deep behavioural analysis; `CompositeOracle` merging both with confidence boosting
- **Reporter** (`agentfuzz/utils/reporter.py`) — Rich colour-coded terminal output with severity
  sorting, category breakdown; JSON report export
- **CLI** (`agentfuzz/cli.py`) — `fuzz` and `list-payloads` commands via Typer; `.env` autoload;
  exit code 2 on vulnerabilities found (CI-friendly)
- **Mock Vulnerable Target** (`tests/target_mock.py`) — FastAPI agent with 7 intentional
  vulnerability classes for immediate testing
- **Payload Library** (`agentfuzz/payloads/jailbreaks.json`) — 22 payloads across 8 attack
  categories
- **GitHub Actions CI** — unit tests (Python 3.12 + 3.13), integration tests, security fuzz run
  with report artifact upload
- **Docker support** — `Dockerfile` + `docker-compose.yml` for zero-setup execution
- Initial documentation: `README.md`, `CONTRIBUTING.md`, `SECURITY.md`, `.env.example`

[Unreleased]: https://github.com/your-org/agentfuzz/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/your-org/agentfuzz/releases/tag/v0.1.0
