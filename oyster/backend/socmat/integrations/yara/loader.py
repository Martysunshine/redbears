"""
YARA rule loader for SOC Copilot Workbench.

Compiles all .yar/.yara files found under rules/yara/ and caches the
compiled ruleset.  Gracefully degrades when yara-python is not installed.
"""

import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import yara as _yara_lib
    _YARA_AVAILABLE = True
except ImportError:
    _yara_lib = None  # type: ignore
    _YARA_AVAILABLE = False

_RULES_DIR = Path(__file__).resolve().parent.parent.parent / "rules" / "yara"

_compiled: Any = None
_rule_metadata: List[Dict[str, Any]] = []


def yara_available() -> bool:
    return _YARA_AVAILABLE


def load_yara_rules() -> List[Dict[str, Any]]:
    """
    Load and compile all YARA rules from rules/yara/.
    Returns a list of rule metadata dicts (name, tags, meta).
    """
    global _compiled, _rule_metadata

    if not _YARA_AVAILABLE:
        print("[yara] yara-python not installed — YARA matching disabled", file=sys.stderr)
        _compiled = None
        _rule_metadata = []
        return []

    rule_files = sorted(_RULES_DIR.glob("**/*.yar")) + sorted(_RULES_DIR.glob("**/*.yara"))
    if not rule_files:
        print(f"[yara] no rule files found in {_RULES_DIR}", file=sys.stderr)
        _compiled = None
        _rule_metadata = []
        return []

    sources: Dict[str, str] = {}
    for f in rule_files:
        try:
            sources[str(f)] = f.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            print(f"[yara] could not read {f}: {exc}", file=sys.stderr)

    if not sources:
        _compiled = None
        _rule_metadata = []
        return []

    try:
        _compiled = _yara_lib.compile(sources=sources)
    except Exception as exc:
        print(f"[yara] compile error: {exc}", file=sys.stderr)
        _compiled = None
        _rule_metadata = []
        return []

    _rule_metadata = []
    for source in sources.values():
        _rule_metadata.extend(_parse_rule_metadata(source))

    print(f"[yara] loaded {len(_rule_metadata)} rule(s) from {len(sources)} file(s)")
    return _rule_metadata


def get_compiled_rules() -> Any:
    return _compiled


def get_rule_metadata() -> List[Dict[str, Any]]:
    return list(_rule_metadata)


# ── internal ──────────────────────────────────────────────────────────────────

def _parse_rule_metadata(source: str) -> List[Dict[str, Any]]:
    """Extract rule names, tags, and meta from YARA source text."""
    results = []
    rule_pat = re.compile(
        r'\brule\s+(\w+)(?:\s*:\s*([\w\s]+?))?\s*\{',
        re.MULTILINE,
    )
    for m in rule_pat.finditer(source):
        name = m.group(1)
        tags_raw = (m.group(2) or "").strip()
        tags = tags_raw.split() if tags_raw else []

        # Extract the rule body starting after the opening brace
        body_start = m.end()
        depth = 1
        pos = body_start
        while pos < len(source) and depth > 0:
            if source[pos] == '{':
                depth += 1
            elif source[pos] == '}':
                depth -= 1
            pos += 1
        body = source[body_start:pos - 1]

        meta: Dict[str, str] = {}
        meta_match = re.search(
            r'\bmeta\s*:(.*?)(?:\bstrings\s*:|\bcondition\s*:)',
            body,
            re.DOTALL,
        )
        if meta_match:
            for kv in re.finditer(r'(\w+)\s*=\s*"([^"]*)"', meta_match.group(1)):
                meta[kv.group(1)] = kv.group(2)

        results.append({"name": name, "tags": tags, "meta": meta})
    return results
