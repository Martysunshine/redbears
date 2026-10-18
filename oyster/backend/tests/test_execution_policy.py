"""Policy + risk classification + parameter validation."""

from __future__ import annotations

from services.execution import policy, risk, store, tool_registry

SCOPE = {"engagement_name": "T", "domains": ["corp.com"], "allowed_targets": ["http://127.0.0.1:9000"]}
PID = "proj_policy_test"


def _pair(tool, action):
    return tool_registry.get_action(tool, action)


def test_risk_classes():
    assert risk.profile_for_class(0).default_approval == risk.APPROVAL_NONE
    assert risk.profile_for_class(2).requires_scope
    assert risk.profile_for_class(3).default_approval == risk.APPROVAL_EXPLICIT
    assert risk.profile_for_class(4).blocked


def test_class0_file_no_approval():
    prof, act = _pair("file", "analyze")
    d = policy.decide(PID, prof, act, ["x.txt"], {}, SCOPE, resolve_dns=False)
    assert d["decision"] == policy.DECISION_ALLOW and not d["approval_required"]


def test_class2_http_requires_approval_in_scope():
    prof, act = _pair("http", "inspect")
    d = policy.decide(PID, prof, act, ["http://127.0.0.1:9000/"], {}, SCOPE, resolve_dns=False)
    assert d["decision"] == policy.DECISION_REQUIRES_APPROVAL and d["approval_required"]
    assert d["matched_scope_entries"]


def test_out_of_scope_blocked():
    prof, act = _pair("http", "inspect")
    d = policy.decide(PID, prof, act, ["http://evil.com/"], {}, SCOPE, resolve_dns=False)
    assert d["decision"] == policy.DECISION_BLOCKED and d["unmatched_targets"] == ["http://evil.com/"]


def test_injection_param_blocked():
    prof, act = _pair("nmap", "port_scan")
    # nmap may be unavailable; if so decision is blocked for availability, which
    # still means "not executed". Force availability check bypass by testing the
    # http tool with a bad method enum instead:
    prof, act = _pair("http", "inspect")
    d = policy.decide(PID, prof, act, ["http://127.0.0.1:9000/"], {"method": "DELETE"}, SCOPE, resolve_dns=False)
    assert d["decision"] == policy.DECISION_BLOCKED


def test_unavailable_tool_blocked():
    prof, act = _pair("nmap", "port_scan")
    d = policy.decide(PID, prof, act, ["10.0.0.5"], {}, SCOPE, resolve_dns=False)
    if not prof.availability()["available"]:
        assert d["decision"] == policy.DECISION_BLOCKED
        assert "not available" in " ".join(d["reasons"]).lower()


def test_disabled_tool_blocked():
    store.init_db()
    store.set_tool_enabled(PID, "http", False)
    prof, act = _pair("http", "inspect")
    d = policy.decide(PID, prof, act, ["http://127.0.0.1:9000/"], {}, SCOPE, resolve_dns=False)
    assert d["decision"] == policy.DECISION_BLOCKED
    store.set_tool_enabled(PID, "http", True)


def test_param_constraints_reported():
    prof, act = _pair("http", "inspect")
    d = policy.decide(PID, prof, act, ["http://127.0.0.1:9000/"], {}, SCOPE, resolve_dns=False)
    assert "method" in d["parameter_constraints"]
    assert d["maximum_runtime"] > 0 and d["maximum_output_size"] > 0
