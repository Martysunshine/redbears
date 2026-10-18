"""Scope engine — normalization + authorization correctness."""

from __future__ import annotations

from services.execution import scope_engine as se

SCOPE = {
    "engagement_name": "Test",
    "domains": ["corp.com", "*.lab.internal"],
    "ip_ranges": ["10.0.0.0/24", "192.168.1.0/24"],
    "allowed_targets": ["http://127.0.0.1:9000"],
    "approved_ports": [80, 443, 8080, 9000],
}


def test_normalize_url():
    p = se.normalize_target("https://api.corp.com:8443/path?x=1")
    assert p.host == "api.corp.com" and p.port == 8443 and p.scheme == "https"
    assert p.path.startswith("/path")


def test_normalize_ipv6():
    p = se.normalize_target("[2001:db8::1]:443")
    assert p.host == "2001:db8::1" and p.is_ip and p.ip_version == 6 and p.port == 443


def test_domain_exact_and_subdomain():
    assert se.validate("corp.com", SCOPE, resolve_dns=False).allowed
    assert se.validate("api.corp.com", SCOPE, resolve_dns=False).allowed
    assert se.validate("a.b.lab.internal", SCOPE, resolve_dns=False).allowed


def test_substring_lookalike_is_blocked():
    # the classic bug: 'evilcorp.com' must NOT match 'corp.com'
    assert not se.validate("evilcorp.com", SCOPE, resolve_dns=False).allowed
    assert not se.validate("corp.com.attacker.net", SCOPE, resolve_dns=False).allowed


def test_ipv4_cidr():
    assert se.validate("10.0.0.5", SCOPE, resolve_dns=False).allowed
    assert not se.validate("10.0.1.5", SCOPE, resolve_dns=False).allowed


def test_port_enforcement():
    r = se.validate("http://api.corp.com:22/", SCOPE, resolve_dns=False)
    assert not r.allowed and "Port" in r.reason


def test_protocol_enforcement():
    scope = dict(SCOPE, approved_protocols=["https"])
    assert not se.validate("http://api.corp.com/", scope, resolve_dns=False).allowed
    assert se.validate("https://api.corp.com/", scope, resolve_dns=False).allowed


def test_prohibited_technique():
    scope = dict(SCOPE, prohibited_techniques=["nmap"])
    r = se.validate("api.corp.com", scope, technique="nmap", resolve_dns=False)
    assert not r.allowed and "prohibited" in r.reason.lower()


def test_allowed_technique_allowlist():
    scope = dict(SCOPE, allowed_techniques=["http"])
    assert not se.validate("api.corp.com", scope, technique="nmap", resolve_dns=False).allowed
    assert se.validate("api.corp.com", scope, technique="http", resolve_dns=False).allowed


def test_blocked_target():
    scope = dict(SCOPE, blocked_targets=["admin.corp.com"])
    assert not se.validate("admin.corp.com", scope, resolve_dns=False).allowed


def test_excluded_path():
    scope = dict(SCOPE, excluded_paths=["/billing"])
    assert not se.validate("https://corp.com/billing/x", scope, resolve_dns=False).allowed


def test_expired_scope():
    scope = dict(SCOPE, expiration="2000-01-01T00:00:00+00:00")
    assert not se.validate("corp.com", scope, resolve_dns=False).allowed


def test_testing_window_not_started():
    scope = dict(SCOPE, start_date="2999-01-01")
    assert not se.validate("corp.com", scope, resolve_dns=False).allowed


def test_no_scope_blocks():
    assert not se.validate("corp.com", {}, resolve_dns=False).allowed


def test_dns_rebinding_blocked(monkeypatch):
    # hostname matches domain, but resolves OUT of the approved IP ranges
    monkeypatch.setattr(se, "_resolve", lambda host: "8.8.8.8")
    r = se.validate("api.corp.com", SCOPE, resolve_dns=True)
    assert not r.allowed and "rebinding" in r.reason.lower()


def test_dns_resolves_in_range(monkeypatch):
    monkeypatch.setattr(se, "_resolve", lambda host: "10.0.0.9")
    assert se.validate("api.corp.com", SCOPE, resolve_dns=True).allowed


def test_redirect_leaving_scope():
    assert not se.validate_redirect("https://evil.com/x", SCOPE).allowed
    assert se.validate_redirect("https://corp.com/x", SCOPE).allowed


def test_matched_rule_recorded():
    r = se.validate("10.0.0.5", SCOPE, resolve_dns=False)
    assert r.matched_rule and r.matched_rule.startswith("ip_range:")
