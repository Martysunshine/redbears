"""
Elastic / Kibana export parser.

Supports Kibana Discover CSV exports, Kibana NDJSON exports, and JSON arrays
as produced by the Elasticsearch _search API.

Normalises 13 ECS fields into a flat dict structure for storage and analysis.

Supported formats
-----------------
- CSV    — Kibana "Discover → Export → CSV" (dotted headers like "host.name")
- JSON   — ES _search response, JSON array, or {"results":[...]} wrapper
- NDJSON — one JSON object per line (.ndjson / .jsonl); also handles _source wrappers
"""

import csv
import io
import json
from typing import Any, Dict, List, Optional


# ECS dotted path → internal column name
_ECS_MAP: Dict[str, str] = {
    "@timestamp": "event_time",
    "host.name": "host_name",
    "user.name": "user_name",
    "source.ip": "src_ip",
    "destination.ip": "dest_ip",
    "process.name": "process_name",
    "process.parent.name": "parent_process_name",
    "process.command_line": "command_line",
    "event.code": "event_code",
    "event.category": "event_category",
    "event.action": "event_action",
    "file.hash.sha256": "file_hash_sha256",
    "dns.question.name": "dns_question",
}

# Flat snake_case aliases that some Kibana versions export
_ALIAS_MAP: Dict[str, str] = {
    "timestamp": "event_time",
    "hostname": "host_name",
    "username": "user_name",
    "src_ip": "src_ip",
    "dest_ip": "dest_ip",
    "process_name": "process_name",
    "parent_process_name": "parent_process_name",
    "command_line": "command_line",
    "event_code": "event_code",
    "event_category": "event_category",
    "event_action": "event_action",
    "sha256": "file_hash_sha256",
    "dns_question": "dns_question",
}


def _get_nested(obj: Dict[str, Any], path: str) -> Optional[str]:
    """Resolve a dotted ECS path like 'host.name' from a nested dict."""
    parts = path.split(".")
    current: Any = obj
    for p in parts:
        if not isinstance(current, dict):
            return None
        current = current.get(p)
    if current is None:
        return None
    val = str(current).strip()
    return val if val else None


def _normalise_row(row: Dict[str, Any]) -> Dict[str, Optional[str]]:
    out: Dict[str, Any] = {v: None for v in set(_ECS_MAP.values())}

    # Dotted ECS paths — flat key (CSV) or nested traversal (JSON)
    for path, col in _ECS_MAP.items():
        flat_val = row.get(path)
        if flat_val is not None and str(flat_val).strip():
            out[col] = str(flat_val).strip()
            continue
        nested = _get_nested(row, path)
        if nested:
            out[col] = nested

    # Alias fallback
    for alias, col in _ALIAS_MAP.items():
        if out[col] is None:
            val = row.get(alias)
            if val is not None and str(val).strip():
                out[col] = str(val).strip()

    try:
        out["raw"] = json.dumps(row)
    except (TypeError, ValueError):
        out["raw"] = str(row)

    return out


def _parse_csv(content: bytes) -> List[Dict[str, Optional[str]]]:
    text = content.decode("utf-8-sig", errors="replace")
    reader = csv.DictReader(io.StringIO(text))
    return [_normalise_row(dict(row)) for row in reader if any(row.values())]


def _parse_json(content: bytes) -> List[Dict[str, Optional[str]]]:
    text = content.decode("utf-8", errors="replace").strip()
    try:
        data = json.loads(text)
        if isinstance(data, list):
            return [_normalise_row(r) for r in data if isinstance(r, dict)]
        if isinstance(data, dict):
            # Elasticsearch _search response: {"hits": {"hits": [{"_source": {...}}]}}
            hits = data.get("hits", {})
            if isinstance(hits, dict):
                inner = hits.get("hits", [])
                if isinstance(inner, list):
                    rows = []
                    for hit in inner:
                        src = hit.get("_source", hit)
                        if isinstance(src, dict):
                            rows.append(_normalise_row(src))
                    return rows
            # Generic wrappers
            for key in ("results", "events", "rows", "data"):
                rows_raw = data.get(key)
                if isinstance(rows_raw, list):
                    return [_normalise_row(r) for r in rows_raw if isinstance(r, dict)]
            return [_normalise_row(data)]
    except json.JSONDecodeError:
        pass
    # NDJSON fallback
    events: List[Dict[str, Optional[str]]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                src = obj.get("_source", obj)
                events.append(_normalise_row(src if isinstance(src, dict) else obj))
        except json.JSONDecodeError:
            continue
    return events


def parse_elastic_export(content: bytes, filename: str) -> List[Dict[str, Optional[str]]]:
    """
    Parse a Kibana / Elasticsearch export.

    Returns a list of normalised event dicts with keys matching ElasticEvent
    column names plus a 'raw' key containing the original row as JSON.
    Returns an empty list on unrecognisable content.
    """
    fname = filename.lower()
    if fname.endswith(".csv"):
        return _parse_csv(content)
    if fname.endswith((".json", ".ndjson", ".jsonl")):
        return _parse_json(content)
    snippet = content[:512].lstrip()
    if snippet and snippet[0:1] in (b"{", b"["):
        return _parse_json(content)
    return _parse_csv(content)
