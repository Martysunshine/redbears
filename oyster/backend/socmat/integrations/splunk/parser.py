"""
Splunk export parser.

Supports Splunk CSV and JSON/NDJSON exports downloaded from the Splunk
search interface. Normalises 11 common Splunk fields into a consistent
dict structure for storage and analysis.

Supported formats
-----------------
- CSV   — Splunk "Export Results → CSV"
- JSON  — Splunk "Export Results → JSON" (array of dicts or {"results":[...]})
- NDJSON — one JSON object per line (also handles .jsonl)

Detection order: file extension → content sniff.
"""

import csv
import io
import json
from typing import Any, Dict, List, Optional


_FIELD_MAP: Dict[str, str] = {
    "_time": "event_time",
    "index": "index",
    "sourcetype": "sourcetype",
    "host": "host",
    "source": "source",
    "user": "user",
    "src_ip": "src_ip",
    "dest_ip": "dest_ip",
    "process_name": "process_name",
    "command_line": "command_line",
    "EventCode": "event_code",
}

# Accept both original and lowercase versions
_FIELD_MAP_LOWER: Dict[str, str] = {k.lower(): v for k, v in _FIELD_MAP.items()}
_FIELD_MAP_LOWER.update(_FIELD_MAP)  # keep original-case keys too


def _normalise_row(row: Dict[str, Any]) -> Dict[str, Optional[str]]:
    out: Dict[str, Any] = {v: None for v in set(_FIELD_MAP.values())}
    for src, dst in _FIELD_MAP_LOWER.items():
        val = row.get(src)
        if val is not None and str(val).strip():
            out[dst] = str(val).strip()
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
    # Try as a JSON document first (array or {"results":[...]})
    try:
        data = json.loads(text)
        if isinstance(data, list):
            return [_normalise_row(r) for r in data if isinstance(r, dict)]
        if isinstance(data, dict):
            for key in ("results", "events", "rows"):
                rows = data.get(key)
                if isinstance(rows, list):
                    return [_normalise_row(r) for r in rows if isinstance(r, dict)]
            return [_normalise_row(data)]
    except json.JSONDecodeError:
        pass
    # Fall back to NDJSON
    events: List[Dict[str, Optional[str]]] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            events.append(_normalise_row(json.loads(line)))
        except json.JSONDecodeError:
            continue
    return events


def parse_splunk_export(content: bytes, filename: str) -> List[Dict[str, Optional[str]]]:
    """
    Parse a Splunk CSV or JSON export.

    Returns a list of normalised event dicts with keys matching SplunkEvent
    column names plus a 'raw' key containing the original row as JSON.
    Returns an empty list on unrecognisable content.
    """
    fname = filename.lower()
    if fname.endswith(".csv"):
        return _parse_csv(content)
    if fname.endswith((".json", ".ndjson", ".jsonl")):
        return _parse_json(content)
    # Sniff: JSON starts with { or [
    snippet = content[:512].lstrip()
    if snippet and snippet[0:1] in (b"{", b"["):
        return _parse_json(content)
    return _parse_csv(content)
