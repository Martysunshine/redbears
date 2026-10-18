"""JSON-file record store for investigation runs and the verified findings
promoted from them. Lives under config.DATA_DIR (outside git, like Oyster's
other runtime state). Every write redacts credentials/session tokens — this
module is the only place investigation records touch disk, so redaction here
covers every caller.
"""
from __future__ import annotations

import json
import re
import threading
import time
import uuid
from pathlib import Path

import config

_PATH = config.DATA_DIR / "investigations.json"
_lock = threading.Lock()

_SECRET_KEY_RE = re.compile(r'"([^"]*(?:token|authorization|password|cookie|session|secret|api_key|bearer)[^"]*)"\s*:\s*"[^"]*"', re.I)
# Substring match, not exact — "bid_token", "access_token", "user_token" must
# all be caught, not just a field literally named "token". This is the same
# mistake a narrower exact-match check would make, so it is checked by
# test_investigation_store.py::test_redacts_keys_containing_sensitive_substrings.
_SENSITIVE_SUBSTRINGS = ("token", "authorization", "password", "cookie", "session", "secret", "api_key", "bearer")


def _redact(obj):
    """Recursively redact dict keys whose name CONTAINS a sensitive substring
    (not just an exact match) from a dict/list structure before it is ever
    written to disk."""
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if isinstance(k, str) and any(s in k.lower() for s in _SENSITIVE_SUBSTRINGS):
                out[k] = "<redacted>"
            else:
                out[k] = _redact(v)
        return out
    if isinstance(obj, list):
        return [_redact(v) for v in obj]
    if isinstance(obj, str):
        return _SECRET_KEY_RE.sub(lambda m: f'"{m.group(1)}":"<redacted>"', obj)
    return obj


def _load() -> dict:
    if not _PATH.exists():
        return {"investigations": {}, "findings": {}}
    try:
        return json.loads(_PATH.read_text())
    except (json.JSONDecodeError, OSError):
        return {"investigations": {}, "findings": {}}


def _save(data: dict) -> None:
    _PATH.parent.mkdir(parents=True, exist_ok=True)
    _PATH.write_text(json.dumps(data, indent=1))


def create_investigation(record: dict) -> str:
    with _lock:
        data = _load()
        inv_id = record.get("id") or uuid.uuid4().hex[:12]
        record = {"id": inv_id, "created_at": record.get("created_at", time.time()), **record}
        data["investigations"][inv_id] = _redact(record)
        _save(data)
        return inv_id


def update_investigation(inv_id: str, patch: dict) -> dict | None:
    with _lock:
        data = _load()
        if inv_id not in data["investigations"]:
            return None
        data["investigations"][inv_id].update(_redact(patch))
        _save(data)
        return data["investigations"][inv_id]


def get_investigation(inv_id: str) -> dict | None:
    return _load()["investigations"].get(inv_id)


def list_investigations() -> list[dict]:
    return sorted(_load()["investigations"].values(), key=lambda r: r.get("created_at", 0), reverse=True)


def create_finding(finding: dict) -> str:
    with _lock:
        data = _load()
        finding_id = finding.get("id") or uuid.uuid4().hex[:12]
        finding = {"id": finding_id, "created_at": finding.get("created_at", time.time()), **finding}
        data["findings"][finding_id] = _redact(finding)
        _save(data)
        return finding_id


def update_finding(finding_id: str, patch: dict) -> dict | None:
    with _lock:
        data = _load()
        if finding_id not in data["findings"]:
            return None
        data["findings"][finding_id].update(_redact(patch))
        _save(data)
        return data["findings"][finding_id]


def get_finding(finding_id: str) -> dict | None:
    return _load()["findings"].get(finding_id)


def list_findings() -> list[dict]:
    return sorted(_load()["findings"].values(), key=lambda r: r.get("created_at", 0), reverse=True)
