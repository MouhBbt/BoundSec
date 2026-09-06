# Security Policy

BoundSec is a **defensive** security-research tool. It is designed to test AI agent systems
you own or are explicitly authorised to assess.

## Scope and safe-by-default design

- The **Agent Gym** is entirely self-contained; its "secrets" are planted canaries with no
  real value, and it makes no network calls.
- The **live-model** adapter wraps a chat model in a tool-calling agent whose tools are
  **sandboxed** — a dangerous tool call is *recorded, not executed*. BoundSec observes the
  model's *choice*, it does not run `rm -rf`.
- Do not point BoundSec at systems you do not have permission to test. Unauthorised testing
  may violate law (CFAA and equivalents).

## Reporting a vulnerability in BoundSec itself

Please open a private security advisory or email the maintainer rather than filing a public
issue. We aim to acknowledge within a few days.
