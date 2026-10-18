"""
Zeek log parser for SOC Copilot Workbench.

Parses Zeek TSV log files (conn.log, dns.log, http.log).
All parsing is static — files are never executed.
"""

from pathlib import Path
from typing import Any, Dict, List, Tuple

_MAX_RECORDS = 50_000
_UNSET = '-'
_EMPTY = '(empty)'


def detect_log_type(filename: str) -> str:
    """Detect Zeek log type from filename stem."""
    name = Path(filename).stem.lower()
    if 'conn' in name:
        return 'conn'
    if 'dns' in name:
        return 'dns'
    if 'http' in name:
        return 'http'
    return 'unknown'


def parse_zeek_log(file_path: str) -> Tuple[List[str], List[Dict[str, Any]]]:
    """
    Parse a Zeek TSV log file.

    Returns (fields, records) where fields is the list of column names from
    the #fields header and records is a list of dicts mapping field -> value.
    """
    fields: List[str] = []
    records: List[Dict[str, Any]] = []
    separator = '\t'

    try:
        with open(file_path, 'r', encoding='utf-8', errors='replace') as fh:
            for line in fh:
                line = line.rstrip('\n\r')

                if line.startswith('#separator'):
                    parts = line.split(None, 1)
                    if len(parts) == 2:
                        try:
                            separator = parts[1].encode('raw_unicode_escape').decode('unicode_escape')
                        except Exception:
                            separator = '\t'
                    continue

                if line.startswith('#fields'):
                    raw = line.split('\t') if '\t' in line else line.split(separator)
                    fields = [p.strip() for p in raw[1:]]
                    continue

                if line.startswith('#') or not line.strip():
                    continue

                if not fields:
                    continue

                if len(records) >= _MAX_RECORDS:
                    break

                parts = line.split(separator)
                record: Dict[str, Any] = {}
                for i, field in enumerate(fields):
                    val = parts[i].strip() if i < len(parts) else ''
                    if val in (_UNSET, _EMPTY):
                        val = ''
                    record[field] = val
                records.append(record)
    except OSError:
        pass

    return fields, records
