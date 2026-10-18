"""
Static file triage for SOC Copilot Workbench.

Computes hashes, detects file type from magic bytes, extracts printable strings,
identifies suspicious indicators, and runs compiled YARA rules — all statically.
Files are NEVER executed.
"""

import hashlib
import re
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Maximum file size processed (100 MB)
_MAX_FILE_BYTES = 100 * 1024 * 1024
# Minimum printable string length
_MIN_STR_LEN = 6
# Maximum extracted strings returned
_MAX_STRINGS = 500
# Maximum strings per suspicious category shown in output
_MAX_CAT = 20

# ── patterns ──────────────────────────────────────────────────────────────────

_IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
_URL_RE = re.compile(r'https?://\S+', re.IGNORECASE)
_B64_RE = re.compile(r'^[A-Za-z0-9+/]{30,}={0,2}$')

_LOLBAS = [
    'rundll32', 'regsvr32', 'mshta', 'wscript', 'certutil',
    'cscript', 'msiexec', 'wmic', 'odbcconf', 'installutil',
]

# ── magic bytes → human-readable type ─────────────────────────────────────────

_MAGIC: List[Tuple[bytes, int, str]] = [
    (b'\x4d\x5a',           2, 'Windows PE Executable'),
    (b'\x7fELF',            4, 'ELF Executable'),
    (b'%PDF',               4, 'PDF Document'),
    (b'PK\x03\x04',         4, 'ZIP/Office Archive'),
    (b'\x89PNG\r\n\x1a\n',  8, 'PNG Image'),
    (b'\xff\xd8\xff',       3, 'JPEG Image'),
    (b'GIF87a',             6, 'GIF Image'),
    (b'GIF89a',             6, 'GIF Image'),
    (b'RIFF',               4, 'RIFF Media'),
    (b'\x1f\x8b',           2, 'Gzip Archive'),
    (b'BZh',                3, 'Bzip2 Archive'),
    (b'\xfd7zXZ\x00',       6, 'XZ Archive'),
    (b'7z\xbc\xaf\x27\x1c', 6, '7-Zip Archive'),
]


# ── public API ────────────────────────────────────────────────────────────────

def compute_hashes(file_path: str) -> Dict[str, Optional[str]]:
    """Return sha256, sha1, md5 for the file. Returns Nones on read failure."""
    try:
        data = _read_file(file_path)
    except OSError:
        return {"sha256": None, "sha1": None, "md5": None}
    return {
        "sha256": hashlib.sha256(data).hexdigest(),
        "sha1":   hashlib.sha1(data).hexdigest(),
        "md5":    hashlib.md5(data).hexdigest(),
    }


def detect_file_type(file_path: str) -> str:
    """Identify file type from magic bytes."""
    try:
        with open(file_path, 'rb') as fh:
            header = fh.read(16)
    except OSError:
        return 'Unknown'

    for magic, length, label in _MAGIC:
        if header[:length] == magic[:length]:
            return label

    # Fallback: try UTF-8 text
    try:
        header.decode('utf-8')
        return 'Text/Script'
    except (UnicodeDecodeError, ValueError):
        pass

    return 'Unknown Binary'


def extract_strings(file_path: str) -> List[str]:
    """
    Extract printable ASCII strings of length >= _MIN_STR_LEN.
    Returns at most _MAX_STRINGS unique strings.
    """
    try:
        data = _read_file(file_path)
    except OSError:
        return []

    results: List[str] = []
    seen: set = set()
    current: List[int] = []

    for byte in data:
        if 0x20 <= byte <= 0x7e:
            current.append(byte)
        else:
            if len(current) >= _MIN_STR_LEN:
                s = bytes(current).decode('ascii')
                if s not in seen:
                    seen.add(s)
                    results.append(s)
                    if len(results) >= _MAX_STRINGS:
                        break
            current = []

    # Handle a trailing string
    if len(current) >= _MIN_STR_LEN and len(results) < _MAX_STRINGS:
        s = bytes(current).decode('ascii')
        if s not in seen:
            results.append(s)

    return results


def detect_suspicious_strings(strings: List[str]) -> Dict[str, List[str]]:
    """
    Categorise extracted strings into suspicious indicator buckets.
    Returns dict with keys: powershell, lolbas, base64, urls, ips.
    """
    ps_hits: List[str] = []
    lolbas_hits: List[str] = []
    b64_hits: List[str] = []
    url_hits: List[str] = []
    ip_hits: List[str] = []

    for s in strings:
        sl = s.lower()

        if 'powershell' in sl and len(ps_hits) < _MAX_CAT:
            ps_hits.append(s[:120])

        for keyword in _LOLBAS:
            if keyword in sl and len(lolbas_hits) < _MAX_CAT:
                lolbas_hits.append(s[:120])
                break

        if _B64_RE.match(s) and len(b64_hits) < _MAX_CAT:
            b64_hits.append(s[:80])

        for url in _URL_RE.findall(s):
            if len(url_hits) < _MAX_CAT:
                url_hits.append(url[:120])

        for ip in _IP_RE.findall(s):
            if len(ip_hits) < _MAX_CAT:
                ip_hits.append(ip)

    return {
        "powershell": ps_hits,
        "lolbas":     lolbas_hits,
        "base64":     list(dict.fromkeys(b64_hits)),   # deduplicate, preserve order
        "urls":       list(dict.fromkeys(url_hits)),
        "ips":        list(dict.fromkeys(ip_hits)),
    }


def run_yara_scan(file_path: str, compiled_rules: Any) -> List[Dict[str, Any]]:
    """
    Run compiled YARA rules against a file.  Returns a list of match dicts.
    Returns an empty list if compiled_rules is None or matching fails.
    """
    if compiled_rules is None:
        return []
    try:
        matches = compiled_rules.match(file_path, timeout=30)
    except Exception as exc:
        print(f"[yara] scan error on {file_path}: {exc}")
        return []

    results = []
    for m in matches:
        strings_matched = _extract_match_strings(m)
        results.append({
            "rule": m.rule,
            "tags": list(m.tags),
            "meta": {k: str(v) for k, v in m.meta.items()},
            "strings_matched": strings_matched,
        })
    return results


def compute_risk_score(
    yara_matches: List[Dict[str, Any]],
    suspicious: Dict[str, List[str]],
) -> int:
    """Compute a 0–100 risk score from YARA matches and suspicious indicators."""
    _sev_points = {
        'critical': 40, 'high': 30, 'medium': 15, 'low': 10, 'informational': 5,
    }
    _cat_points = {
        'powershell': 5, 'lolbas': 10, 'base64': 10, 'urls': 5, 'ips': 3,
    }

    yara_score = 0
    for m in yara_matches:
        sev = m.get('meta', {}).get('severity', 'medium').lower()
        yara_score += _sev_points.get(sev, 10)
    yara_score = min(yara_score, 60)

    indicator_score = 0
    for cat, items in suspicious.items():
        if items:
            indicator_score += _cat_points.get(cat, 3)
    indicator_score = min(indicator_score, 35)

    return min(yara_score + indicator_score, 100)


def generate_summary(
    original_filename: str,
    file_type: str,
    yara_matches: List[Dict[str, Any]],
    suspicious: Dict[str, List[str]],
    risk_score: int,
) -> str:
    """Generate a human-readable triage summary."""
    parts = []

    if risk_score == 0:
        parts.append(f"No suspicious indicators detected in '{original_filename}'.")
    elif risk_score < 26:
        parts.append(f"Low-risk indicators detected in '{original_filename}'.")
    elif risk_score < 51:
        parts.append(f"Medium-risk indicators detected in '{original_filename}'. Review recommended.")
    elif risk_score < 76:
        parts.append(f"High-risk indicators detected in '{original_filename}'. Review required.")
    else:
        parts.append(f"Critical-risk indicators detected in '{original_filename}'. Immediate review required.")

    if yara_matches:
        names = [m['rule'] for m in yara_matches[:3]]
        extra = f" (+{len(yara_matches) - 3} more)" if len(yara_matches) > 3 else ""
        parts.append(f"YARA matches: {', '.join(names)}{extra}.")

    found = [cat for cat, items in suspicious.items() if items]
    if found:
        parts.append(f"Suspicious indicators: {', '.join(found)}.")

    parts.append(f"File type: {file_type}. Static analysis only — file was not executed.")
    return " ".join(parts)


# ── internal helpers ──────────────────────────────────────────────────────────

def _read_file(file_path: str) -> bytes:
    """Read file up to _MAX_FILE_BYTES."""
    size = Path(file_path).stat().st_size
    if size > _MAX_FILE_BYTES:
        raise OSError(f"File too large for triage ({size} bytes > {_MAX_FILE_BYTES})")
    with open(file_path, 'rb') as fh:
        return fh.read(_MAX_FILE_BYTES)


def _safe_str(data: bytes, max_len: int = 40) -> str:
    """Convert bytes to a printable representation."""
    result = []
    for b in data[:max_len]:
        if 0x20 <= b <= 0x7e:
            result.append(chr(b))
        else:
            result.append(f'\\x{b:02x}')
    if len(data) > max_len:
        result.append('...')
    return ''.join(result)


def _extract_match_strings(match: Any) -> List[str]:
    """Extract matched string descriptions from a yara match object."""
    results: List[str] = []
    seen: set = set()
    try:
        for s in match.strings:
            if len(results) >= 10:
                break
            try:
                # yara-python >= 4.x: StringMatch objects
                ident = s.identifier
                for inst in list(s.instances)[:3]:
                    label = f"{ident}: {_safe_str(inst.matched_data)}"
                    if label not in seen:
                        seen.add(label)
                        results.append(label)
            except AttributeError:
                # yara-python < 4.x: (offset, identifier, data) tuples
                try:
                    _, ident, data = s
                    label = f"{ident}: {_safe_str(data)}"
                    if label not in seen:
                        seen.add(label)
                        results.append(label)
                except (TypeError, ValueError):
                    pass
    except Exception:
        pass
    return results
