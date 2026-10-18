"""Official NIST Special Publication PDF connector.

For narrative NIST SPs with no OSCAL/JSON export (SP 800-61 Incident
Response, SP 800-207 Zero Trust Architecture) — these are US government
works and explicitly marked "not subject to copyright in the United States"
in their own front matter. Downloads the real PDF from ``nvlpubs.nist.gov``,
extracts text via pypdf (already a project dependency), and splits on the
document's own numbered section headings (``1 Introduction``,
``3.1.2 ZTA Using Micro-Segmentation``, …) so each materialized doc is one
real section, not an arbitrary character-count slice.

Table-of-contents entries share the same "N.N Title" shape as real headings
but are excluded by filtering the DOTTED-LEADER lines (``....... 12``, the
row's page-number reference) — a real body heading is never followed by a
line of dot leaders on the same line.
"""

from __future__ import annotations

import hashlib
import re
from pathlib import Path
from urllib.parse import urlparse

import requests

import config

from . import injection_scan
from .base import NormalizedDoc, SourceConnector

_HEADING_RE = re.compile(r"^\s*(\d{1,2}(?:\.\d{1,2}){0,3})\.?\s+([A-Z][A-Za-z0-9].{2,90}?)\s*$")


def _is_heading(line: str) -> tuple[str, str] | None:
    if ".." in line:  # ToC dot-leader row
        return None
    m = _HEADING_RE.match(line)
    if not m:
        return None
    num, title = m.groups()
    if int(num.split(".")[0]) > 20:  # excludes stray "100 Bureau Drive..." addresses etc.
        return None
    return num, title.strip()


class PdfConnector(SourceConnector):
    def health(self) -> dict:
        return {"available": True, "reason": None}

    def _host_allowed(self, url: str) -> bool:
        if not self.profile.allowed_hosts:
            return True
        host = (urlparse(url).hostname or "").lower()
        return host in {h.lower() for h in self.profile.allowed_hosts}

    def discover_version(self) -> str | None:
        url = self.profile.repo_url
        try:
            r = requests.head(url, timeout=config.KNOWLEDGE_CONNECTOR_NET_TIMEOUT,
                              allow_redirects=True)
            if r.status_code == 200:
                return r.headers.get("etag", "").strip('"') or r.headers.get("last-modified")
        except requests.RequestException:
            return None
        return None

    def acquire(self, workdir) -> str:
        url = self.profile.repo_url
        if not self._host_allowed(url):
            raise PermissionError(f"{url} host not in connector allow-list")
        r = requests.get(url, timeout=config.KNOWLEDGE_CONNECTOR_CLONE_TIMEOUT)
        r.raise_for_status()
        content = r.content
        max_bytes = self.profile.max_file_bytes or 32 * 1024 * 1024
        if len(content) > max_bytes:
            raise RuntimeError("PDF exceeds size budget")
        dest = Path(workdir) / "source.pdf"
        dest.write_bytes(content)
        return hashlib.sha256(content).hexdigest()[:12]

    def normalize(self, acquired, workdir) -> list[NormalizedDoc]:
        import pypdf

        path = Path(workdir) / "source.pdf"
        reader = pypdf.PdfReader(str(path))
        lines: list[str] = []
        for page in reader.pages:
            lines.extend((page.extract_text() or "").split("\n"))

        sections: list[tuple[str, str, list[str]]] = []  # (num, title, body_lines)
        for line in lines:
            heading = _is_heading(line)
            if heading:
                sections.append((heading[0], heading[1], []))
            elif sections:
                sections[-1][2].append(line)

        max_files = self.profile.max_files or config.KNOWLEDGE_CONNECTOR_MAX_FILES
        docs: list[NormalizedDoc] = []
        for num, title, body_lines in sections:
            if len(docs) >= max_files:
                break
            body = "\n".join(l.rstrip() for l in body_lines if l.strip())
            body = re.sub(r"\n{3,}", "\n\n", body).strip()
            if len(body) < 40:  # heading with no real prose under it (e.g. a figure caption)
                continue
            content = f"# {num} {title}\n\n{body}\n"
            clean, findings = injection_scan.neutralize(content)
            docs.append(NormalizedDoc(
                rel_path=f"sections/{num.replace('.', '-')}.md",
                title=f"{self.profile.display_name} — {num} {title}",
                section=f"{num} {title}",
                heading_path=(num, title),
                content=clean,
                source_url=self.profile.upstream_url,
                source_path=num,
                injection=findings,
            ))
        return docs
