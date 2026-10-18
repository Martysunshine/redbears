"""MITRE D3FEND source connector (official structured CSV mapping export).

The D3FEND ontology itself is published as raw OWL/Turtle source, which would
need a full RDF parser to consume directly. MITRE also publishes a pre-built,
official structured export of the same ontology data directly from
d3fend.mitre.org: a CSV of every (D3FEND defensive technique) <-> (ATT&CK
offensive technique) inference, already resolved with human-readable labels.
This connector uses that export instead of parsing the ontology source.

Each row already carries: the D3FEND tactic (Harden/Detect/Isolate/Deceive/
Evict/Model), the artifact the technique acts on and how, and the ATT&CK
technique/tactic it counters. Normalizes into one document per D3FEND
technique, aggregating every ATT&CK technique it maps to — entirely from real
CSV rows, never invented. Citations point at the technique's real
d3fend.mitre.org page (`/technique/d3f:<LocalName>/`, derived from the row's
own ontology IRI, not guessed).
"""

from __future__ import annotations

import csv
import hashlib
import io
from pathlib import Path
from urllib.parse import urlparse

import requests

import config

from . import injection_scan
from .base import NormalizedDoc, SourceConnector

_CSV_URL = "https://d3fend.mitre.org/api/ontology/inference/d3fend-full-mappings.csv"
_MAX_CSV_BYTES = 64 * 1024 * 1024  # generous bound; live export is ~15MB
_IRI_PREFIX = "http://d3fend.mitre.org/ontologies/d3fend.owl#"


def _local_name(iri: str) -> str | None:
    if iri and iri.startswith(_IRI_PREFIX):
        return iri[len(_IRI_PREFIX):]
    return None


class D3fendConnector(SourceConnector):
    def health(self) -> dict:
        return {"available": True, "reason": None}

    def discover_version(self) -> str | None:
        """Cheap freshness check via ETag/Last-Modified — no 15MB download."""
        try:
            r = requests.head(_CSV_URL, timeout=config.KNOWLEDGE_CONNECTOR_NET_TIMEOUT,
                              allow_redirects=True)
            if r.status_code == 200:
                etag = r.headers.get("etag")
                if etag:
                    return etag.strip('"')
                lm = r.headers.get("last-modified")
                if lm:
                    return lm
        except requests.RequestException:
            return None
        return None

    def _host_allowed(self) -> bool:
        if not self.profile.allowed_hosts:
            return True
        host = (urlparse(_CSV_URL).hostname or "").lower()
        return host in {h.lower() for h in self.profile.allowed_hosts}

    # --- acquisition -----------------------------------------------------
    def acquire(self, workdir) -> str:
        if not self._host_allowed():
            raise PermissionError("d3fend.mitre.org not in connector allow-list")
        r = requests.get(_CSV_URL, timeout=config.KNOWLEDGE_CONNECTOR_CLONE_TIMEOUT)
        r.raise_for_status()
        content = r.content
        if len(content) > _MAX_CSV_BYTES:
            raise RuntimeError("D3FEND CSV exceeds size budget")
        dest = Path(workdir) / "d3fend-full-mappings.csv"
        dest.write_bytes(content)
        # Content hash as the version ref — the export has no upstream commit id.
        return hashlib.sha256(content).hexdigest()[:12]

    # --- normalization -----------------------------------------------------
    def normalize(self, acquired, workdir) -> list[NormalizedDoc]:
        path = Path(workdir) / "d3fend-full-mappings.csv"
        if not path.exists():
            raise RuntimeError("D3FEND CSV missing after acquire")
        text = path.read_text(encoding="utf-8", errors="replace")

        techniques: dict[str, dict] = {}
        order: list[str] = []
        reader = csv.DictReader(io.StringIO(text))
        for row in reader:
            label = (row.get("def_tech_label") or "").strip()
            if not label:
                continue
            entry = techniques.get(label)
            if entry is None:
                entry = {
                    "iri": row.get("def_tech") or "",
                    "tactics": set(),
                    "artifact_rels": set(),
                    "attack": {},  # off_tech_id -> (label, parent_label, tactic_label)
                }
                techniques[label] = entry
                order.append(label)
            tactic = (row.get("def_tactic_label") or "").strip()
            if tactic:
                entry["tactics"].add(tactic)
            art_rel = (row.get("def_artifact_rel_label") or "").strip()
            art = (row.get("def_artifact_label") or "").strip()
            if art_rel and art:
                entry["artifact_rels"].add(f"{art_rel} {art}")
            off_id = (row.get("off_tech_id") or "").strip()
            if off_id:
                entry["attack"][off_id] = (
                    (row.get("off_tech_label") or "").strip(),
                    (row.get("off_tech_parent_label") or "").strip(),
                    (row.get("off_tactic_label") or "").strip(),
                )

        max_files = self.profile.max_files or config.KNOWLEDGE_CONNECTOR_MAX_FILES
        total_budget = config.KNOWLEDGE_CONNECTOR_MAX_TOTAL_BYTES
        docs: list[NormalizedDoc] = []
        total = 0
        for label in sorted(order):
            if len(docs) >= max_files or total >= total_budget:
                break
            entry = techniques[label]
            local = _local_name(entry["iri"])
            url = (f"https://d3fend.mitre.org/technique/d3f:{local}/"
                   if local else self.profile.upstream_url)
            content = self._render(label, entry)
            clean, findings = injection_scan.neutralize(content)
            docs.append(NormalizedDoc(
                rel_path=f"techniques/{local or label}.md",
                title=f"D3FEND — {label}",
                section=label,
                heading_path=(label,),
                content=clean,
                source_url=url,
                source_path=local or label,
                injection=findings,
            ))
            total += len(clean)
        return docs

    def _render(self, label: str, entry: dict) -> str:
        lines = [f"# D3FEND — {label}", ""]
        if entry["tactics"]:
            lines.append(f"**D3FEND tactic:** {', '.join(sorted(entry['tactics']))}")
        if entry["artifact_rels"]:
            lines.append(f"**Acts on:** {', '.join(sorted(entry['artifact_rels']))}")
        lines.append("")
        if entry["attack"]:
            lines.append("## Counters ATT&CK techniques")
            for off_id in sorted(entry["attack"]):
                off_label, parent_label, tactic_label = entry["attack"][off_id]
                desc = off_label or off_id
                extra = []
                if parent_label and parent_label != off_label:
                    extra.append(f"sub-technique of {parent_label}")
                if tactic_label:
                    extra.append(f"ATT&CK tactic: {tactic_label}")
                suffix = f" ({'; '.join(extra)})" if extra else ""
                lines.append(f"- **{off_id}** — {desc}{suffix}")
            lines.append("")
        lines.append(
            "Source: MITRE D3FEND official ontology mapping export "
            "(d3fend.mitre.org/api/ontology/inference/d3fend-full-mappings.csv)."
        )
        return "\n".join(lines).strip() + "\n"
