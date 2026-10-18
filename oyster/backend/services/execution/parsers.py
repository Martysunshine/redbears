"""Turn raw/structured tool output into typed observations.

Observations are the bridge between a run and evidence. Each is a small dict
``{type, title, detail, severity}``. Parsing is best-effort and never invents
data — if it can't parse, it returns an empty list and the raw output stands on
its own.
"""

from __future__ import annotations

import re


def parse(tool_id: str, action_id: str, parsed: dict, stdout: str) -> list[dict]:
    try:
        if tool_id == "http":
            return _parse_http(parsed)
        if tool_id == "tls":
            return _parse_tls(parsed)
        if tool_id == "file":
            return _parse_file(parsed)
        if tool_id == "nmap":
            return _parse_nmap(stdout)
        if tool_id == "semgrep":
            return _parse_semgrep(stdout)
    except Exception:
        return []
    return []


def _parse_http(p: dict) -> list[dict]:
    obs: list[dict] = []
    if not p:
        return obs
    status = p.get("status")
    obs.append({"type": "http_status", "title": f"HTTP {status} from {p.get('final_url')}",
                "detail": f"{p.get('method')} · server={p.get('server')} · type={p.get('content_type')}",
                "severity": "info"})
    if p.get("server"):
        obs.append({"type": "tech", "title": f"Server header: {p['server']}",
                    "detail": "Server/technology disclosed via Server header.", "severity": "low"})
    missing = p.get("security_headers_missing") or []
    if missing:
        obs.append({"type": "security_headers", "title": f"{len(missing)} security header(s) missing",
                    "detail": "Missing: " + ", ".join(missing), "severity": "medium"})
    if p.get("redirect_blocked"):
        rb = p["redirect_blocked"]
        obs.append({"type": "scope", "title": "Out-of-scope redirect refused",
                    "detail": f"{rb.get('location')} — {rb.get('reason')}", "severity": "info"})
    tls = p.get("tls") or {}
    if tls.get("expired"):
        obs.append({"type": "tls", "title": "TLS certificate expired",
                    "detail": f"not_after={tls.get('not_after')}", "severity": "high"})
    return obs


def _parse_tls(p: dict) -> list[dict]:
    obs: list[dict] = []
    if not p:
        return obs
    obs.append({"type": "tls", "title": f"{p.get('tls_version')} · {p.get('cipher')}",
                "detail": f"subject={p.get('subject_cn')} issuer={p.get('issuer_cn')}", "severity": "info"})
    if p.get("expired"):
        obs.append({"type": "tls", "title": "Certificate expired",
                    "detail": f"not_after={p.get('not_after')}", "severity": "high"})
    elif isinstance(p.get("days_until_expiry"), int) and p["days_until_expiry"] < 30:
        obs.append({"type": "tls", "title": f"Certificate expires in {p['days_until_expiry']} days",
                    "detail": f"not_after={p.get('not_after')}", "severity": "medium"})
    if p.get("certificate_validated") is False:
        obs.append({"type": "tls", "title": "Certificate chain did not validate",
                    "detail": "Handshake succeeded but chain validation failed.", "severity": "medium"})
    return obs


def _parse_file(p: dict) -> list[dict]:
    obs: list[dict] = []
    if not p:
        return obs
    obs.append({"type": "file_hash", "title": f"{p.get('filename')} · sha256",
                "detail": p.get("sha256", ""), "severity": "info"})
    indicators = p.get("secret_indicators") or []
    if indicators:
        types = ", ".join(sorted({i.get("type", "?") for i in indicators}))
        obs.append({"type": "secret", "title": f"{len(indicators)} possible secret indicator(s)",
                    "detail": f"types: {types} (values masked)", "severity": "high"})
    return obs


_NMAP_PORT = re.compile(r"^(\d+)/(tcp|udp)\s+(\w+)\s+(.*)$", re.MULTILINE)


def _parse_nmap(stdout: str) -> list[dict]:
    obs: list[dict] = []
    for m in _NMAP_PORT.finditer(stdout or ""):
        port, proto, state, svc = m.groups()
        if state == "open":
            obs.append({"type": "port", "title": f"{port}/{proto} open — {svc.strip()}",
                        "detail": f"state={state}", "severity": "low"})
    hosts_up = re.search(r"(\d+)\s+hosts?\s+up", stdout or "")
    if hosts_up:
        obs.append({"type": "host", "title": f"{hosts_up.group(1)} host(s) up", "detail": "", "severity": "info"})
    return obs


def _parse_semgrep(stdout: str) -> list[dict]:
    obs: list[dict] = []
    try:
        import json
        data = json.loads(stdout or "{}")
        for r in (data.get("results") or [])[:50]:
            obs.append({"type": "sast",
                        "title": r.get("check_id", "finding"),
                        "detail": f"{r.get('path')}:{(r.get('start') or {}).get('line')}",
                        "severity": (r.get("extra") or {}).get("severity", "info").lower()})
    except Exception:
        return []
    return obs
