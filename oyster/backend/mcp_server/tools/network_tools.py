from __future__ import annotations
from mcp_server.tools._safe_env import safe_env

import subprocess

from ..security import validate_network_target

_TIMEOUT = 30


def _run(tokens: list[str]) -> dict:
    try:
        proc = subprocess.run(
            tokens,
            capture_output=True,
            text=True,
            timeout=_TIMEOUT,
            shell=False,
            env=safe_env(),
        )
        return {
            "stdout": proc.stdout[:8_000],
            "stderr": proc.stderr[:2_000],
            "returncode": proc.returncode,
        }
    except subprocess.TimeoutExpired:
        return {"error": f"Command timed out after {_TIMEOUT}s"}
    except FileNotFoundError as exc:
        return {"error": f"Command not found: {exc}"}


def ping(target: str) -> dict:
    ok, reason = validate_network_target(target)
    if not ok:
        return {"error": reason, "blocked": True, "target": target}
    result = _run(["ping", "-c", "3", "-W", "3", target])
    return {"target": target, "scope_ok": True, **result}


def dig(target: str, record_type: str = "A") -> dict:
    ok, reason = validate_network_target(target)
    if not ok:
        return {"error": reason, "blocked": True, "target": target}
    # Sanitise record type — alphanumeric only
    safe_type = "".join(c for c in record_type.upper() if c.isalnum())[:10] or "A"
    result = _run(["dig", target, safe_type, "+short"])
    return {"target": target, "record_type": safe_type, "scope_ok": True, **result}


def whois(target: str) -> dict:
    ok, reason = validate_network_target(target)
    if not ok:
        return {"error": reason, "blocked": True, "target": target}
    result = _run(["whois", target])
    return {"target": target, "scope_ok": True, **result}


def nmap_basic(target: str) -> dict:
    ok, reason = validate_network_target(target)
    if not ok:
        return {"error": reason, "blocked": True, "target": target}
    result = _run(["nmap", "-Pn", "-T3", target])
    return {"target": target, "scan_type": "basic", "command": f"nmap -Pn -T3 {target}", "scope_ok": True, **result}


def nmap_service(target: str) -> dict:
    ok, reason = validate_network_target(target)
    if not ok:
        return {"error": reason, "blocked": True, "target": target}
    result = _run(["nmap", "-sV", "-T3", target])
    return {"target": target, "scan_type": "service_detection", "command": f"nmap -sV -T3 {target}", "scope_ok": True, **result}


def nmap_top_ports(target: str, count: int = 100) -> dict:
    ok, reason = validate_network_target(target)
    if not ok:
        return {"error": reason, "blocked": True, "target": target}
    safe_count = max(1, min(int(count), 1000))
    result = _run(["nmap", "--top-ports", str(safe_count), "-T3", target])
    return {
        "target": target,
        "scan_type": f"top_{safe_count}_ports",
        "command": f"nmap --top-ports {safe_count} -T3 {target}",
        "scope_ok": True,
        **result,
    }
