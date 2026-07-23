# Security Policy

## Scope

This document covers the security of the **AgentFuzz framework itself** — not the vulnerabilities
it is designed to detect in other systems.

AgentFuzz is a security research tool. The `tests/target_mock.py` file is **intentionally and
deliberately vulnerable** as a controlled test target. Findings in that file are by design and
are not considered security vulnerabilities in AgentFuzz.

## Reporting a Vulnerability

If you discover a security vulnerability in the AgentFuzz framework code itself (e.g. a path
traversal in the harness, arbitrary code execution via a crafted payload file, credential leakage
in log output), please **do not open a public GitHub issue**.

Instead, report it via one of these channels:

1. **GitHub Private Security Advisory** (preferred):
   `https://github.com/your-org/agentfuzz/security/advisories/new`

2. **Email**: `security@your-org.example.com`

Please include:
- A description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Any suggested mitigations you have in mind

We aim to acknowledge all reports within **72 hours** and provide a fix or mitigation within
**14 days** for critical issues.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | ✅ Yes    |

## Responsible Use Reminder

AgentFuzz must only be used against AI systems you own or have **explicit written authorisation**
to test. Unauthorised use against third-party systems may violate computer fraud laws in your
jurisdiction (CFAA, Computer Misuse Act, GDPR, etc.).
