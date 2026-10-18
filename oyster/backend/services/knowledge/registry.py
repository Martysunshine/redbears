"""Discover Knowledge Packs on disk and parse their (rich) manifests.

Layout::

    knowledge_packs/<pack_id>/
        pack.json          # manifest (see the metadata schema below)
        <doc>.md           # one or more curated knowledge documents

The manifest carries machine-readable metadata so a pack can be independently
searched, versioned, risk-classified, licence-tracked and freshness-checked.
Only ``id``, ``version`` and ``title`` are strictly required; everything else has
a safe default so the 12 original packs keep working unchanged.

We never copy whole copyrighted upstreams — packs hold concise extracted
passages / original summaries plus permitted metadata, source URLs and
provenance. ``content_checksum`` is a deterministic hash of the docs so the
manual update workflow can detect curated-content drift.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import config

REQUIRED = ("id", "version", "title")

# Authorities we treat as first-party/standards bodies → higher trust weight.
_OFFICIAL_AUTHORITIES = {
    "owasp", "nist", "mitre", "mitre att&ck", "kali", "offensive security",
    "first", "cisa", "pci ssc", "cloud security alliance",
}


def _packs_dir() -> Path:
    return config.KNOWLEDGE_PACKS_DIR


def _checksum(pack_dir: Path, docs: list[dict], version: str) -> str:
    h = hashlib.sha256()
    h.update(version.encode("utf-8"))
    for d in sorted(docs, key=lambda x: x.get("file") or ""):
        h.update((d.get("file") or "").encode("utf-8"))
        p = pack_dir / (d.get("file") or "")
        if p.exists():
            try:
                h.update(p.read_bytes())
            except OSError:
                pass
    return h.hexdigest()


def _infer_trust(authority: str | None, declared: str | None) -> str:
    if declared:
        return declared
    if authority and authority.strip().lower() in _OFFICIAL_AUTHORITIES:
        return "official"
    return "community"


def _parse_manifest(pack_dir: Path) -> dict | None:
    manifest = pack_dir / "pack.json"
    if not manifest.exists():
        return None
    try:
        data = json.loads(manifest.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {"id": pack_dir.name, "valid": False, "error": "unreadable pack.json",
                "title": pack_dir.name, "version": "0", "docs": []}
    if not all(k in data for k in REQUIRED):
        return {"id": data.get("id", pack_dir.name), "valid": False,
                "error": "manifest missing required fields", "title": pack_dir.name,
                "version": data.get("version", "0"), "docs": []}

    docs = []
    ok = True
    for d in data.get("docs", []):
        fp = pack_dir / d.get("file", "")
        exists = fp.exists()
        ok = ok and exists
        docs.append({
            "file": d.get("file"),
            "path": str(fp),
            "exists": exists,
            "source_title": d.get("source_title"),
            "source_url": d.get("source_url"),
            "section": d.get("section") or d.get("source_title"),
            "risk_level": d.get("risk_level"),  # per-doc override (payload docs)
        })

    authority = data.get("authority")
    domain = data.get("domain", "general")
    # source_urls: explicit, else derived from docs.
    source_urls = data.get("source_urls") or [
        d["source_url"] for d in docs if d.get("source_url")
    ]

    return {
        "id": data["id"],
        "name": data.get("name", data["title"]),
        "version": data["version"],
        "title": data["title"],
        "domain": domain,
        "security_domain": data.get("security_domain", domain),
        "description": data.get("description", ""),
        "tags": data.get("tags", []),
        "authority": authority,
        "publisher": data.get("publisher", authority),
        "trust_level": _infer_trust(authority, data.get("trust_level")),
        "licence": data.get("licence") or data.get("license"),
        "attribution": data.get("attribution"),
        "trusted_sources": data.get("trusted_sources") or source_urls,
        "source_urls": source_urls,
        "retrieved_at": data.get("retrieved_at"),
        "last_reviewed_at": data.get("last_reviewed_at"),
        "freshness_policy": data.get("freshness_policy"),
        "supported_tasks": data.get("supported_tasks", []),
        "intended_audience": data.get("intended_audience", []),
        "prerequisites": data.get("prerequisites", []),
        "applicable_tools": data.get("applicable_tools", []),
        "applicable_platforms": data.get("applicable_platforms", []),
        "risk_classification": data.get("risk_classification", "informational"),
        "active_execution_possible": bool(data.get("active_execution_possible", False)),
        "approval_requirements": data.get("approval_requirements"),
        "scope_requirements": data.get("scope_requirements"),
        "docs": docs,
        "doc_count": len(docs),
        "content_checksum": _checksum(pack_dir, docs, data["version"]),
        "valid": ok and len(docs) > 0,
    }


def list_packs() -> list[dict]:
    root = _packs_dir()
    if not root.exists():
        return []
    packs = []
    for child in sorted(root.iterdir()):
        if child.is_dir():
            m = _parse_manifest(child)
            if m is not None:
                packs.append(m)
    return packs


def get_pack(pack_id: str) -> dict | None:
    root = _packs_dir()
    if not root.exists():
        return None
    for child in root.iterdir():
        if child.is_dir():
            m = _parse_manifest(child)
            if m and m.get("id") == pack_id:
                return m
    return None
