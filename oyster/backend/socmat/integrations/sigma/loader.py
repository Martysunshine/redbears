"""
Sigma rule loader.

Recursively scans rules/sigma/ for .yml/.yaml files, parses them, and
returns normalised rule dicts suitable for the API and explainer.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import yaml
except ImportError:
    yaml = None  # type: ignore

_RULES_DIR = Path(__file__).resolve().parent.parent.parent / "rules" / "sigma"

_cache: List[Dict[str, Any]] = []


def _parse_rule(path: Path) -> Optional[Dict[str, Any]]:
    if yaml is None:
        return None
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
        data = yaml.safe_load(text)
    except Exception:
        return None
    if not isinstance(data, dict) or not data.get("title"):
        return None

    rule_id = str(data.get("id") or path.stem)

    raw_tags = data.get("tags") or []
    tags = [str(t) for t in raw_tags] if isinstance(raw_tags, list) else []

    raw_refs = data.get("references") or []
    references = [str(r) for r in raw_refs] if isinstance(raw_refs, list) else []

    raw_fp = data.get("falsepositives") or []
    falsepositives = [str(f) for f in raw_fp] if isinstance(raw_fp, list) else []

    logsource = data.get("logsource") or {}
    detection = data.get("detection") or {}

    return {
        "id": rule_id,
        "title": str(data.get("title", "")),
        "status": str(data.get("status") or ""),
        "description": str(data.get("description") or ""),
        "references": references,
        "author": str(data.get("author") or ""),
        "date": str(data.get("date") or ""),
        "modified": str(data.get("modified") or ""),
        "tags": tags,
        "logsource": dict(logsource) if isinstance(logsource, dict) else {},
        "detection": dict(detection) if isinstance(detection, dict) else {},
        "falsepositives": falsepositives,
        "level": str(data.get("level") or "medium"),
        "file_path": str(path),
    }


def load_rules() -> List[Dict[str, Any]]:
    """Scan rules/sigma/ recursively, parse all YAML files, cache and return results."""
    global _cache
    rules: List[Dict[str, Any]] = []
    if not _RULES_DIR.exists():
        _cache = rules
        return rules

    for path in sorted(_RULES_DIR.rglob("*.yml")):
        r = _parse_rule(path)
        if r:
            rules.append(r)
    for path in sorted(_RULES_DIR.rglob("*.yaml")):
        r = _parse_rule(path)
        if r:
            rules.append(r)

    # Deduplicate by id — first occurrence wins (alphabetical scan order)
    seen: set = set()
    deduped: List[Dict[str, Any]] = []
    for r in rules:
        if r["id"] not in seen:
            seen.add(r["id"])
            deduped.append(r)

    _cache = deduped
    return _cache


def get_cached_rules() -> List[Dict[str, Any]]:
    """Return cached rules, loading from disk on first call."""
    if not _cache:
        load_rules()
    return _cache


def get_rule_by_id(rule_id: str) -> Optional[Dict[str, Any]]:
    for r in get_cached_rules():
        if r["id"] == rule_id:
            return r
    return None
