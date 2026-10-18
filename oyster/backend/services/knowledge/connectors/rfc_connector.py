"""Official IETF RFC connector.

Fetches the canonical plain-text RFC from ``www.rfc-editor.org`` — RFCs are
freely reproducible per the IETF Trust Legal Provisions (TLP), which grant a
perpetual, non-exclusive licence to copy and publish RFC text with
attribution. Splits on the RFC's own page-formfeed layout to strip the
repeated per-page header/footer (``RFC 8446 ... TLS ... August 2018`` /
``... [Page N]``), then on the document's own numbered section headings
(``4.1.2.  Client Hello``) — a very regular, machine-stable format across all
RFCs, unlike arbitrary PDF layouts.
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

_HEADER_RE = re.compile(r"^RFC \d+.*$", re.MULTILINE)
_FOOTER_RE = re.compile(r"^\S.*\[Page \d+\]\s*$", re.MULTILINE)
_HEADING_RE = re.compile(r"^(\d{1,2}(?:\.\d{1,2}){0,3})\.?\s{2,}([A-Z][A-Za-z0-9].{2,90}?)\s*$")


class RfcConnector(SourceConnector):
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
        max_bytes = self.profile.max_file_bytes or 4 * 1024 * 1024
        if len(content) > max_bytes:
            raise RuntimeError("RFC text exceeds size budget")
        dest = Path(workdir) / "rfc.txt"
        dest.write_bytes(content)
        return hashlib.sha256(content).hexdigest()[:12]

    def normalize(self, acquired, workdir) -> list[NormalizedDoc]:
        path = Path(workdir) / "rfc.txt"
        text = path.read_text(encoding="utf-8", errors="replace")
        text = text.replace("\x0c", "\n")
        text = _HEADER_RE.sub("", text)
        text = _FOOTER_RE.sub("", text)
        lines = text.split("\n")

        sections: list[tuple[str, str, list[str]]] = []
        for line in lines:
            m = _HEADING_RE.match(line)
            if m:
                sections.append((m.group(1), m.group(2).strip(), []))
            elif sections:
                sections[-1][2].append(line)

        max_files = self.profile.max_files or config.KNOWLEDGE_CONNECTOR_MAX_FILES
        docs: list[NormalizedDoc] = []
        for num, title, body_lines in sections:
            if len(docs) >= max_files:
                break
            body = "\n".join(l.rstrip() for l in body_lines if l.strip())
            body = re.sub(r"\n{3,}", "\n\n", body).strip()
            if len(body) < 40:
                continue
            content = f"# {self.profile.display_name} — {num} {title}\n\n{body}\n"
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
