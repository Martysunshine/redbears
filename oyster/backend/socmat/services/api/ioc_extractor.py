"""
IOC extraction from case data.

Extracts IOCs from: Evidence, NormalizedEvent, MalwareTriageResult,
NetworkAnalysisResult, CorrelatedFinding, DetectionFinding, AnalystNote.
Deduplicates by (case_id, ioc_type, normalized_value).

Confidence levels:
  high   — extracted from a structured field (e.g. sha256 column, source_ip column)
  medium — extracted from semi-structured text (command lines, summaries)
  low    — extracted by regex from free text (notes, match reasons)
"""

import ipaddress
import json
import re
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from sqlalchemy.orm import Session

from socmat.services.api.models.analyst_note import AnalystNote
from socmat.services.api.models.correlated_finding import CorrelatedFinding
from socmat.services.api.models.detection_finding import DetectionFinding
from socmat.services.api.models.evidence import Evidence
from socmat.services.api.models.ioc import Ioc
from socmat.services.api.models.malware_triage_result import MalwareTriageResult
from socmat.services.api.models.network_analysis_result import NetworkAnalysisResult
from socmat.services.api.models.normalized_event import NormalizedEvent

# ── Regex patterns ─────────────────────────────────────────────────────────────

_RE_SHA256 = re.compile(r'\b[0-9a-fA-F]{64}\b')
_RE_SHA1 = re.compile(r'\b[0-9a-fA-F]{40}\b')
_RE_MD5 = re.compile(r'\b[0-9a-fA-F]{32}\b')
_RE_IPV4 = re.compile(
    r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
)
_RE_IPV6 = re.compile(
    r'\b(?:[0-9a-fA-F]{1,4}:){3,7}(?:[0-9a-fA-F]{1,4}|:)\b'
)
_RE_URL = re.compile(r'(?:https?|hxxps?|ftp)://[^\s<>"\'`\]]+', re.IGNORECASE)
_RE_EMAIL = re.compile(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b')
_RE_DOMAIN = re.compile(
    r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.){1,4}[a-zA-Z]{2,6}\b'
)
_RE_REGISTRY = re.compile(
    r'\b(?:HKEY_(?:LOCAL_MACHINE|CURRENT_USER|CLASSES_ROOT|USERS|CURRENT_CONFIG)|HK(?:LM|CU|CR|U|CC))\\[^\s"\'<>\r\n]+',
    re.IGNORECASE,
)
_RE_WIN_PATH = re.compile(r'[A-Za-z]:\\(?:[^\\\/:*?"<>|\r\n]+\\)*[^\\\/:*?"<>|\r\n]+')

# Domains that are structural noise, not real IOCs
_BENIGN_DOMAIN_SUFFIXES = frozenset({
    "microsoft.com", "windows.com", "windowsupdate.com", "update.microsoft.com",
    "google.com", "googleapis.com", "gstatic.com", "github.com",
    "apple.com", "icloud.com", "amazon.com", "amazonaws.com",
})


# ── Normalisation ──────────────────────────────────────────────────────────────

def _normalize_value(value: str, ioc_type: str) -> str:
    """Return a canonical lowercase form used for deduplication."""
    v = value.strip()
    # expand defanged indicators
    v = re.sub(r'hxxp(s?)://', r'http\1://', v, flags=re.IGNORECASE)
    v = re.sub(r'\[\.\]', '.', v)
    v = re.sub(r'\[dot\]', '.', v, flags=re.IGNORECASE)
    if ioc_type in (
        "ipv4", "ipv6", "domain", "email", "url",
        "hostname", "md5", "sha1", "sha256", "user_agent",
    ):
        v = v.lower()
    return v


def _is_private_ip(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False


def _is_benign_domain(domain: str) -> bool:
    d = domain.lower()
    if d in _BENIGN_DOMAIN_SUFFIXES:
        return True
    for suffix in _BENIGN_DOMAIN_SUFFIXES:
        if d.endswith("." + suffix):
            return True
    return False


def _auto_tags(ioc_type: str, normalized: str) -> List[str]:
    tags: List[str] = []
    if ioc_type in ("ipv4", "ipv6") and _is_private_ip(normalized):
        tags.append("internal")
    return tags


# ── Text scanning ──────────────────────────────────────────────────────────────

def _scan_text(
    text: str,
    source_type: Optional[str],
    source_id: Optional[int],
    confidence: str = "low",
) -> List[Dict]:
    """Extract IOC candidates from a free-text string via regex."""
    if not text:
        return []
    candidates: List[Dict] = []

    def cand(ioc_type, value):
        candidates.append({
            "ioc_type": ioc_type,
            "value": value,
            "source_type": source_type,
            "source_id": source_id,
            "confidence": confidence,
        })

    # Hashes — longest first to avoid false sub-matches
    for m in _RE_SHA256.finditer(text):
        cand("sha256", m.group())
    scrubbed = _RE_SHA256.sub(" " * 64, text)

    for m in _RE_SHA1.finditer(scrubbed):
        cand("sha1", m.group())
    scrubbed = _RE_SHA1.sub(" " * 40, scrubbed)

    for m in _RE_MD5.finditer(scrubbed):
        cand("md5", m.group())

    # URLs before domains (URLs contain domains)
    for m in _RE_URL.finditer(text):
        cand("url", m.group())
    no_url = _RE_URL.sub(" ", text)

    # Emails before domains (emails contain @)
    for m in _RE_EMAIL.finditer(no_url):
        cand("email", m.group())
    no_email = _RE_EMAIL.sub(" ", no_url)

    # IPs
    for m in _RE_IPV4.finditer(no_email):
        cand("ipv4", m.group())
    for m in _RE_IPV6.finditer(no_email):
        val = m.group()
        # Basic sanity: must have at least 3 colon-separated groups
        if val.count(":") >= 3:
            cand("ipv6", val)

    # Registry paths (before file paths — they start similarly)
    for m in _RE_REGISTRY.finditer(text):
        cand("registry_path", m.group())

    # Windows file paths
    for m in _RE_WIN_PATH.finditer(text):
        p = m.group()
        # Skip very short paths and common noise
        if len(p) > 5 and not p.endswith("\\"):
            cand("file_path", p)

    # Domains — lowest confidence, skip benign
    for m in _RE_DOMAIN.finditer(no_email):
        d = m.group()
        # Skip if it looks like an IP, a known benign domain, or a single word
        if not _RE_IPV4.match(d) and "." in d and not _is_benign_domain(d):
            cand("domain", d)

    return candidates


# ── Main extraction ────────────────────────────────────────────────────────────

def extract_iocs(db: Session, case_id: int) -> Tuple[int, int]:
    """
    Extract IOCs from all case data sources. Returns (new_count, total_count).
    Only inserts IOCs not already stored for this case.
    """
    existing = db.query(Ioc).filter(Ioc.case_id == case_id).all()
    existing_keys = {(r.ioc_type, r.normalized_value) for r in existing}

    # Accumulate candidates; key = (ioc_type, normalized_value)
    bucket: Dict[Tuple[str, str], Dict] = {}

    def add(
        ioc_type: str,
        value: str,
        source_type: Optional[str],
        source_id: Optional[int],
        confidence: str = "medium",
        ts: Optional[datetime] = None,
    ) -> None:
        if not value:
            return
        value = str(value).strip()
        if len(value) < 2:
            return
        norm = _normalize_value(value, ioc_type)
        if not norm or len(norm) < 2:
            return
        key = (ioc_type, norm)
        if key in existing_keys or key in bucket:
            return
        bucket[key] = {
            "case_id": case_id,
            "ioc_type": ioc_type,
            "value": value,
            "normalized_value": norm,
            "source_type": source_type,
            "source_id": source_id,
            "confidence": confidence,
            "tags": _auto_tags(ioc_type, norm),
            "first_seen": ts,
            "last_seen": ts,
        }

    def add_from_text(text: str, source_type: str, source_id: Optional[int], confidence: str = "low"):
        for c in _scan_text(text, source_type, source_id, confidence):
            add(c["ioc_type"], c["value"], source_type, source_id, c["confidence"])

    # ── Evidence ──────────────────────────────────────────────────────────────
    for ev in db.query(Evidence).filter(Evidence.case_id == case_id).all():
        if ev.sha256:
            add("sha256", ev.sha256, "evidence", ev.id, "high", ev.uploaded_at)
        if ev.original_filename:
            add("file_path", ev.original_filename, "evidence", ev.id, "high", ev.uploaded_at)

    # ── NormalizedEvent (Windows/Sysmon) ──────────────────────────────────────
    _SKIP_USERS = frozenset({"-", "n/a", "system", "local service", "network service", ""})
    for ne in db.query(NormalizedEvent).filter(NormalizedEvent.case_id == case_id).all():
        ts = ne.timestamp or ne.created_at
        if ne.host:
            add("hostname", ne.host, "normalized_event", ne.id, "high", ts)
        if ne.user and ne.user.lower() not in _SKIP_USERS:
            add("username", ne.user, "normalized_event", ne.id, "high", ts)
        if ne.process_name:
            add("process_name", ne.process_name, "normalized_event", ne.id, "high", ts)
        if ne.parent_process_name:
            add("process_name", ne.parent_process_name, "normalized_event", ne.id, "medium", ts)
        if ne.source_ip:
            add("ipv4", ne.source_ip, "normalized_event", ne.id, "high", ts)
        if ne.destination_ip:
            add("ipv4", ne.destination_ip, "normalized_event", ne.id, "high", ts)
        if ne.destination_port:
            add("port", str(ne.destination_port), "normalized_event", ne.id, "high", ts)
        if ne.command_line:
            add_from_text(ne.command_line, "normalized_event", ne.id, "medium")

    # ── MalwareTriageResult (YARA) ────────────────────────────────────────────
    for yr in db.query(MalwareTriageResult).filter(MalwareTriageResult.case_id == case_id).all():
        ts = yr.created_at
        if yr.sha256:
            add("sha256", yr.sha256, "malware_triage_result", yr.id, "high", ts)
        if yr.sha1:
            add("sha1", yr.sha1, "malware_triage_result", yr.id, "high", ts)
        if yr.md5:
            add("md5", yr.md5, "malware_triage_result", yr.id, "high", ts)
        if yr.summary:
            add_from_text(yr.summary, "malware_triage_result", yr.id, "medium")

    # ── NetworkAnalysisResult (Zeek / Suricata / PCAP) ────────────────────────
    for nr in db.query(NetworkAnalysisResult).filter(NetworkAnalysisResult.case_id == case_id).all():
        ts = nr.created_at
        # Structured summary_data fields
        if nr.summary_data:
            try:
                sd = json.loads(nr.summary_data) if isinstance(nr.summary_data, str) else nr.summary_data
                if isinstance(sd, dict):
                    for entry in sd.get("top_talkers", []):
                        if isinstance(entry, dict):
                            for field in ("src", "dst", "src_ip", "dst_ip", "ip"):
                                if entry.get(field):
                                    add("ipv4", entry[field], "network_analysis_result", nr.id, "high", ts)
                    for entry in sd.get("dns_summary", []):
                        if isinstance(entry, dict) and entry.get("domain"):
                            d = entry["domain"]
                            if not _is_benign_domain(d):
                                add("domain", d, "network_analysis_result", nr.id, "high", ts)
                    for entry in sd.get("http_summary", []):
                        if isinstance(entry, dict):
                            if entry.get("host") and not _is_benign_domain(entry["host"]):
                                add("domain", entry["host"], "network_analysis_result", nr.id, "high", ts)
                            if entry.get("user_agent"):
                                add("user_agent", entry["user_agent"], "network_analysis_result", nr.id, "medium", ts)
            except Exception:
                pass
        if nr.summary:
            add_from_text(nr.summary, "network_analysis_result", nr.id, "medium")
        if nr.findings:
            add_from_text(nr.findings, "network_analysis_result", nr.id, "medium")

    # ── CorrelatedFinding ─────────────────────────────────────────────────────
    _ENTITY_TYPE_MAP = {
        "ip": "ipv4", "ip_address": "ipv4", "ipv4": "ipv4",
        "ipv6": "ipv6",
        "domain": "domain", "hostname": "hostname", "host": "hostname",
        "url": "url",
        "user": "username", "username": "username",
        "process": "process_name",
        "hash": "sha256", "sha256": "sha256", "sha1": "sha1", "md5": "md5",
        "file_path": "file_path", "file": "file_path",
        "registry": "registry_path",
    }
    for cf in db.query(CorrelatedFinding).filter(CorrelatedFinding.case_id == case_id).all():
        ts = cf.created_at
        if cf.entities:
            try:
                entities = json.loads(cf.entities) if isinstance(cf.entities, str) else cf.entities
                for ent in entities if isinstance(entities, list) else []:
                    if isinstance(ent, dict):
                        etype = ent.get("type", "").lower()
                        evalue = ent.get("value", "")
                        if evalue:
                            mapped = _ENTITY_TYPE_MAP.get(etype)
                            if mapped:
                                add(mapped, str(evalue), "correlated_finding", cf.id, "high", ts)
            except Exception:
                pass
        if cf.summary:
            add_from_text(cf.summary, "correlated_finding", cf.id, "low")

    # ── DetectionFinding (Sigma) ──────────────────────────────────────────────
    for df in db.query(DetectionFinding).filter(DetectionFinding.case_id == case_id).all():
        if df.match_reason:
            add_from_text(df.match_reason, "detection_finding", df.id, "low")

    # ── AnalystNote ───────────────────────────────────────────────────────────
    for an in db.query(AnalystNote).filter(AnalystNote.case_id == case_id).all():
        add_from_text(an.body, "analyst_note", an.id, "low")

    # ── Persist new IOCs ──────────────────────────────────────────────────────
    new_count = 0
    for entry in bucket.values():
        tags = entry.pop("tags", [])
        ioc_row = Ioc(
            **entry,
            tags_json=json.dumps(tags),
        )
        db.add(ioc_row)
        new_count += 1

    if new_count:
        db.commit()

    total = db.query(Ioc).filter(Ioc.case_id == case_id).count()
    return new_count, total
