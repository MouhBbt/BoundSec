"""
BoundSec - Core data model.

Every object that crosses a module boundary is defined here so that the
harness, the coverage engine, the oracles and the analysis layer all agree
on a single serialisable representation of "what happened".

Design note
-----------
The central abstraction is the :class:`AgentTrace`.  Classical fuzzers observe
a program through its *exit status* and its *edge coverage bitmap*.  An LLM
agent has neither, so an ``AgentTrace`` is deliberately rich: it records the
full action sequence (tool calls with arguments and outcomes), the natural
language surface (final answer, intermediate reasoning), transport-level
signals (status, latency, token usage) and - when the target is an
instrumented gym agent - a :class:`GroundTruth` record of what actually
happened inside the agent.  The coverage engine (``core/coverage.py``)
projects this object down to a discrete bitmap; the oracles
(``core/oracle.py``) project it to a vulnerability score.
"""

from __future__ import annotations

import hashlib
import uuid
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field

# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class Severity(str, Enum):
    """CVSS-inspired qualitative severity, ordered by :meth:`rank`."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"
    UNKNOWN = "unknown"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
    Severity.UNKNOWN: 5,
}


class VulnClass(str, Enum):
    """
    The vulnerability classes BoundSec can adjudicate.

    These are the *observable outcomes* of an attack, deliberately kept
    distinct from the *technique* used to achieve them (see
    :class:`AttackTechnique`).  A single technique (e.g. encoding-based
    obfuscation) can produce several outcomes, and a single outcome can be
    reached by several techniques - keeping the two axes separate is what
    makes the technique x outcome heatmaps in the evaluation meaningful.
    """

    SYSTEM_PROMPT_LEAK = "system_prompt_leak"
    CREDENTIAL_LEAK = "credential_leak"
    UNAUTHORIZED_TOOL_CALL = "unauthorized_tool_call"
    DANGEROUS_COMMAND_EXEC = "dangerous_command_exec"
    PATH_TRAVERSAL = "path_traversal"
    SSRF_EXFILTRATION = "ssrf_exfiltration"
    JAILBREAK_COMPLIANCE = "jailbreak_compliance"
    INDIRECT_INJECTION = "indirect_injection"
    ROLE_CONFUSION = "role_confusion"
    MEMORY_POISONING = "memory_poisoning"
    EXCESSIVE_AGENCY = "excessive_agency"
    DENIAL_OF_SERVICE = "denial_of_service"
    OUTPUT_INTEGRITY = "output_integrity"

    @property
    def default_severity(self) -> Severity:
        return _VULN_SEVERITY.get(self, Severity.MEDIUM)


_VULN_SEVERITY: dict[VulnClass, Severity] = {
    VulnClass.SYSTEM_PROMPT_LEAK: Severity.HIGH,
    VulnClass.CREDENTIAL_LEAK: Severity.CRITICAL,
    VulnClass.UNAUTHORIZED_TOOL_CALL: Severity.HIGH,
    VulnClass.DANGEROUS_COMMAND_EXEC: Severity.CRITICAL,
    VulnClass.PATH_TRAVERSAL: Severity.HIGH,
    VulnClass.SSRF_EXFILTRATION: Severity.CRITICAL,
    VulnClass.JAILBREAK_COMPLIANCE: Severity.HIGH,
    VulnClass.INDIRECT_INJECTION: Severity.CRITICAL,
    VulnClass.ROLE_CONFUSION: Severity.MEDIUM,
    VulnClass.MEMORY_POISONING: Severity.HIGH,
    VulnClass.EXCESSIVE_AGENCY: Severity.HIGH,
    VulnClass.DENIAL_OF_SERVICE: Severity.MEDIUM,
    VulnClass.OUTPUT_INTEGRITY: Severity.MEDIUM,
}


class AttackTechnique(str, Enum):
    """
    Attack *techniques* - how the adversary phrases the request.

    Grouped into families that mirror the mutation-operator families in
    ``core/operators.py`` so that operator-level ablations can be reported
    against technique-level success rates.
    """

    DIRECT_REQUEST = "direct_request"
    INSTRUCTION_OVERRIDE = "instruction_override"
    ROLEPLAY_FRAMING = "roleplay_framing"
    AUTHORITY_IMPERSONATION = "authority_impersonation"
    HYPOTHETICAL_FRAMING = "hypothetical_framing"
    ENCODING_OBFUSCATION = "encoding_obfuscation"
    UNICODE_EVASION = "unicode_evasion"
    STRUCTURAL_INJECTION = "structural_injection"
    INDIRECT_CONTENT = "indirect_content"
    TOOL_SCHEMA_ABUSE = "tool_schema_abuse"
    MULTI_TURN_ESCALATION = "multi_turn_escalation"
    CONTEXT_SATURATION = "context_saturation"
    PERSUASION = "persuasion"
    LANGUAGE_PIVOT = "language_pivot"


class ResponseMode(str, Enum):
    """
    Coarse behavioural classification of an agent's natural-language reply.

    This is the *guardrail state* dimension of behavioural coverage: it lets
    the fuzzer recognise that it has driven the agent into a qualitatively
    new response regime even when no vulnerability fired.  The ordering from
    ``HARD_REFUSAL`` to ``FULL_COMPLIANCE`` is monotone in "how much the
    guardrail gave way", which the corpus scheduler exploits as a gradient.
    """

    HARD_REFUSAL = "hard_refusal"
    SOFT_REFUSAL = "soft_refusal"
    DEFLECTION = "deflection"
    CLARIFICATION = "clarification"
    PARTIAL_COMPLIANCE = "partial_compliance"
    FULL_COMPLIANCE = "full_compliance"
    META_DISCLOSURE = "meta_disclosure"
    TRANSPORT_ERROR = "transport_error"

    @property
    def compliance_level(self) -> int:
        """0 = fully refused ... 5 = fully complied. Used as a search gradient."""
        return _COMPLIANCE_LEVEL[self]


_COMPLIANCE_LEVEL: dict[ResponseMode, int] = {
    ResponseMode.TRANSPORT_ERROR: 0,
    ResponseMode.HARD_REFUSAL: 0,
    ResponseMode.SOFT_REFUSAL: 1,
    ResponseMode.DEFLECTION: 1,
    ResponseMode.CLARIFICATION: 2,
    ResponseMode.PARTIAL_COMPLIANCE: 3,
    ResponseMode.META_DISCLOSURE: 4,
    ResponseMode.FULL_COMPLIANCE: 5,
}


class ToolOutcome(str, Enum):
    OK = "ok"
    ERROR = "error"
    BLOCKED = "blocked"
    TIMEOUT = "timeout"


# ---------------------------------------------------------------------------
# Execution records
# ---------------------------------------------------------------------------


class ToolCall(BaseModel):
    """One tool invocation observed in an agent trace."""

    model_config = ConfigDict(frozen=False)

    tool_name: str
    arguments: dict[str, Any] = Field(default_factory=dict)
    result: str | None = None
    error: str | None = None
    outcome: ToolOutcome = ToolOutcome.OK
    turn_index: int = 0

    def arg_signature(self) -> str:
        """Stable, order-independent signature of the argument *names*."""
        return ",".join(sorted(self.arguments.keys()))


class GroundTruth(BaseModel):
    """
    Oracle-quality labels emitted by instrumented gym targets.

    Real black-box LLM endpoints cannot supply this - which is precisely why
    the evaluation in ``experiments/`` runs against the deterministic Agent
    Gym: it is the only setting in which detector precision and recall are
    *measurable* rather than estimated.  ``available=False`` marks a trace
    from a live target, for which only detector scores exist.
    """

    available: bool = False
    vulnerabilities: list[VulnClass] = Field(default_factory=list)
    policy_violations: list[str] = Field(default_factory=list)
    canaries_leaked: list[str] = Field(default_factory=list)
    defense_layers_triggered: list[str] = Field(default_factory=list)
    complied: bool = False
    notes: str = ""

    def is_vulnerable(self) -> bool:
        return bool(self.vulnerabilities)


class TokenUsage(BaseModel):
    prompt_tokens: int = 0
    completion_tokens: int = 0

    @property
    def total(self) -> int:
        return self.prompt_tokens + self.completion_tokens


class AgentTrace(BaseModel):
    """
    Complete observation of one interaction (possibly multi-turn) with a target.

    See the module docstring for why this is the pivot object of the system.
    """

    trace_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    case_id: str = ""
    prompts: list[str] = Field(default_factory=list)
    responses: list[str] = Field(default_factory=list)
    tool_calls: list[ToolCall] = Field(default_factory=list)
    reasoning: str = ""
    raw_response: str = ""
    latency_ms: float = 0.0
    status_code: int = 200
    error: str | None = None
    usage: TokenUsage = Field(default_factory=TokenUsage)
    ground_truth: GroundTruth = Field(default_factory=GroundTruth)
    metadata: dict[str, Any] = Field(default_factory=dict)

    # -- convenience accessors ------------------------------------------

    @property
    def prompt(self) -> str:
        """The final (most recent) prompt sent to the target."""
        return self.prompts[-1] if self.prompts else ""

    @property
    def final_output(self) -> str:
        """The final assistant message."""
        return self.responses[-1] if self.responses else ""

    @property
    def all_output(self) -> str:
        """Every assistant message concatenated - what output filters scan."""
        return "\n".join(self.responses)

    @property
    def n_turns(self) -> int:
        return len(self.prompts)

    def scannable_text(self) -> str:
        """
        All text an exfiltration detector should inspect: assistant messages,
        exposed reasoning, and tool results (a leak via a tool result that the
        agent echoes is still a leak).
        """
        parts = [self.all_output, self.reasoning]
        parts.extend(tc.result or "" for tc in self.tool_calls)
        return "\n".join(p for p in parts if p)

    def summary(self) -> str:
        return (
            f"status={self.status_code} turns={self.n_turns} "
            f"tools={len(self.tool_calls)} latency={self.latency_ms:.0f}ms "
            f"out_len={len(self.all_output)}"
        )


# ---------------------------------------------------------------------------
# Fuzz cases
# ---------------------------------------------------------------------------


class FuzzCase(BaseModel):
    """
    One concrete test input: an ordered list of user turns plus provenance.

    Multi-turn attacks are first-class - ``turns`` holds the full escalation
    ladder.  ``lineage`` records the chain of mutation operators applied to
    reach this case from a seed, which is what makes per-operator credit
    assignment (``core/scheduler.py``) possible.
    """

    case_id: str = Field(default_factory=lambda: uuid.uuid4().hex[:12])
    seed_id: str = ""
    turns: list[str] = Field(default_factory=list)
    technique: AttackTechnique = AttackTechnique.DIRECT_REQUEST
    objective: VulnClass | None = None
    category: str = "uncategorised"
    severity: Severity = Severity.UNKNOWN
    description: str = ""
    source: str = "static"  # static | mutated | llm | crossover | escalation
    lineage: list[str] = Field(default_factory=list)
    generation: int = 0
    parent_id: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @property
    def prompt(self) -> str:
        """Single-turn view of the case (the last turn carries the payload)."""
        return self.turns[-1] if self.turns else ""

    @property
    def n_turns(self) -> int:
        return len(self.turns)

    @property
    def is_multi_turn(self) -> bool:
        return len(self.turns) > 1

    def content_hash(self) -> str:
        """Deterministic identity of the *content*, used to deduplicate."""
        joined = "\x00".join(self.turns)
        return hashlib.blake2b(joined.encode("utf-8"), digest_size=8).hexdigest()


# ---------------------------------------------------------------------------
# Verdicts
# ---------------------------------------------------------------------------


class Verdict(BaseModel):
    """
    A detector's judgement about one (case, trace) pair.

    ``score`` is a *continuous* [0, 1] suspiciousness value and is what the
    ROC / PR / calibration analysis consumes; ``is_vulnerable`` is the
    thresholded decision.  Keeping both is what allows the evaluation to
    report threshold-free detector quality rather than a single operating
    point chosen by hand.
    """

    case_id: str
    trace_id: str = ""
    is_vulnerable: bool = False
    score: float = Field(ge=0.0, le=1.0, default=0.0)
    vuln_classes: list[VulnClass] = Field(default_factory=list)
    severity: Severity = Severity.UNKNOWN
    evidence: list[str] = Field(default_factory=list)
    detector: str = "unknown"
    reasoning: str = ""
    per_class_scores: dict[str, float] = Field(default_factory=dict)
    latency_ms: float = 0.0

    @property
    def top_class(self) -> VulnClass | None:
        return self.vuln_classes[0] if self.vuln_classes else None


class Observation(BaseModel):
    """
    A fully-evaluated fuzzing step: input, observation, judgement, coverage.

    This is the atomic row of every results file the analysis layer reads.
    """

    case: FuzzCase
    trace: AgentTrace
    verdict: Verdict
    new_coverage: int = 0
    total_coverage: int = 0
    step: int = 0
    wall_time_s: float = 0.0
    queries_used: int = 1

    @property
    def response_mode(self) -> ResponseMode:
        raw = self.trace.metadata.get("response_mode")
        return ResponseMode(raw) if raw else ResponseMode.FULL_COMPLIANCE
