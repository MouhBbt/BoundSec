"""Core data-model invariants."""
from boundsec.core.types import (
    AgentTrace, FuzzCase, Severity, ToolCall, ToolOutcome, VulnClass, Verdict)


def test_severity_ordering():
    assert Severity.CRITICAL.rank < Severity.HIGH.rank < Severity.LOW.rank


def test_vulnclass_default_severity():
    assert VulnClass.CREDENTIAL_LEAK.default_severity is Severity.CRITICAL
    assert VulnClass.ROLE_CONFUSION.default_severity is Severity.MEDIUM


def test_fuzzcase_content_hash_stable_and_distinct():
    a = FuzzCase(turns=["hello", "world"])
    b = FuzzCase(turns=["hello", "world"])
    c = FuzzCase(turns=["hello", "there"])
    assert a.content_hash() == b.content_hash()
    assert a.content_hash() != c.content_hash()


def test_fuzzcase_multiturn_prompt_is_last_turn():
    fc = FuzzCase(turns=["a", "b", "c"])
    assert fc.prompt == "c"
    assert fc.is_multi_turn and fc.n_turns == 3


def test_trace_accessors():
    t = AgentTrace(prompts=["p1", "p2"], responses=["r1", "r2"],
                   tool_calls=[ToolCall(tool_name="x", result="leaked-secret")])
    assert t.prompt == "p2" and t.final_output == "r2"
    assert "r1" in t.all_output and "r2" in t.all_output
    assert "leaked-secret" in t.scannable_text()
    assert t.n_turns == 2


def test_verdict_score_bounds():
    v = Verdict(case_id="x", score=0.5)
    assert 0.0 <= v.score <= 1.0
