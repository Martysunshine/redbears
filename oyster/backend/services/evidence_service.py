from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

import config

EVIDENCE_FILE = config.EVIDENCE_JSON
EVIDENCE_FILE.parent.mkdir(parents=True, exist_ok=True)


def _load() -> list[dict]:
    if not EVIDENCE_FILE.exists():
        return []
    try:
        return json.loads(EVIDENCE_FILE.read_text(encoding="utf-8"))
    except Exception:
        return []


def _save(findings: list[dict]) -> None:
    EVIDENCE_FILE.write_text(json.dumps(findings, indent=2), encoding="utf-8")


def list_findings() -> list[dict]:
    return _load()


def log_finding(finding: dict) -> dict:
    findings = _load()
    entry = {
        "id": str(uuid.uuid4())[:8],
        "logged_at": datetime.now(timezone.utc).isoformat(),
        **finding,
    }
    findings.insert(0, entry)
    _save(findings)
    return entry


def delete_finding(finding_id: str) -> bool:
    findings = _load()
    updated = [f for f in findings if f.get("id") != finding_id]
    if len(updated) == len(findings):
        return False
    _save(updated)
    return True
