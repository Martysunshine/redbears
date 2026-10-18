"""MITRE ATT&CK STIX source connector.

Acquires the official ATT&CK STIX 2.1 bundle from ``mitre-attack/attack-stix-data``
with a **shallow, partial, sparse** git checkout (only the one bundle file is
fetched — the repo carries every historical version and every domain, so we never
pull the whole tree), then parses the STIX graph into one provenance-tagged
document per (sub-)technique that carries its real relationships:

    technique  ──mitigated-by──▶  mitigation (Mxxxx)
    technique  ──detected-by──▶   data component / data source
    technique  ──used-by──────▶   group (Gxxxx) / software (Sxxxx)
    sub-technique ──child-of──▶   parent technique

Nothing from the bundle is executed. The bundle is inert JSON; each technique's
prose is injection-neutralized (bidi / zero-width stripped) before it is stored.
Citations point at the canonical ``attack.mitre.org`` technique page.
"""

from __future__ import annotations

import json
from pathlib import Path
from urllib.parse import urlparse

import config

from . import injection_scan
from .base import NormalizedDoc, SourceConnector
from .git_connector import _git

# A STIX bundle for one domain can legitimately be tens of MB — allow a bounded
# single-file read well above the per-markdown-file cap, but still finite.
_MAX_BUNDLE_BYTES = 128 * 1024 * 1024


class StixConnector(SourceConnector):
    # --- capability / health -------------------------------------------------
    def health(self) -> dict:
        try:
            r = _git("--version", timeout=10)
            if r.returncode == 0:
                return {"available": True, "reason": None, "git": r.stdout.strip()}
            return {"available": False, "reason": "git not runnable"}
        except (OSError, Exception) as e:  # noqa: BLE001
            return {"available": False, "reason": f"git unavailable: {e}"}

    def discover_version(self) -> str | None:
        repo = self.profile.repo_url
        if not repo:
            return None
        try:
            r = _git("ls-remote", repo, self.profile.default_ref,
                     timeout=config.KNOWLEDGE_CONNECTOR_NET_TIMEOUT)
            if r.returncode != 0 or not r.stdout.strip():
                r = _git("ls-remote", repo, "HEAD",
                         timeout=config.KNOWLEDGE_CONNECTOR_NET_TIMEOUT)
            if r.returncode == 0 and r.stdout.strip():
                return r.stdout.split()[0]
        except (OSError, Exception):  # noqa: BLE001
            return None
        return None

    def _host_allowed(self) -> bool:
        if not self.profile.allowed_hosts:
            return True
        host = (urlparse(self.profile.repo_url or "").hostname or "").lower()
        return host in {h.lower() for h in self.profile.allowed_hosts}

    def _bundle_rel(self) -> str:
        globs = self.profile.include_globs or ()
        if not globs:
            raise ValueError("STIX connector needs include_globs[0] = bundle path")
        return globs[0]

    # --- acquisition ---------------------------------------------------------
    def acquire(self, workdir) -> str:
        if not self._host_allowed():
            raise PermissionError(
                f"repo host not in connector allow-list: {self.profile.repo_url}")
        repo = self.profile.repo_url
        if not repo:
            raise ValueError("connector has no repo_url")
        dest = str(Path(workdir) / "repo")
        bundle_rel = self._bundle_rel()
        ct = config.KNOWLEDGE_CONNECTOR_CLONE_TIMEOUT

        # Preferred: partial + sparse clone → fetch only the one bundle blob.
        used_sparse = False
        r = _git("clone", "--depth", "1", "--filter=blob:none", "--sparse",
                 "--branch", self.profile.default_ref, "--single-branch",
                 repo, dest, timeout=ct)
        if r.returncode == 0:
            used_sparse = True
        else:
            # Fallback: plain shallow clone (works on older git; larger tree).
            r = _git("clone", "--depth", "1", "--branch", self.profile.default_ref,
                     "--single-branch", repo, dest, timeout=ct)
            if r.returncode != 0:
                r = _git("clone", "--depth", "1", repo, dest, timeout=ct)
                if r.returncode != 0:
                    raise RuntimeError(f"git clone failed: {r.stderr.strip()[:300]}")

        if used_sparse:
            # Non-cone mode with a leading-slash anchor selects the single bundle
            # file (cone mode only accepts directories). Falls back to a full
            # checkout if sparse selection fails.
            sp = _git("sparse-checkout", "set", "--no-cone", "/" + bundle_rel,
                      cwd=dest, timeout=60)
            _git("checkout", cwd=dest, timeout=ct)
            if sp.returncode != 0 and not (Path(dest) / bundle_rel).exists():
                _git("sparse-checkout", "disable", cwd=dest, timeout=60)
                _git("checkout", cwd=dest, timeout=ct)

        if not (Path(dest) / bundle_rel).exists():
            raise RuntimeError(f"STIX bundle not found after checkout: {bundle_rel}")

        sha = _git("rev-parse", "HEAD", cwd=dest, timeout=30)
        return sha.stdout.strip() if sha.returncode == 0 else self.profile.default_ref

    # --- normalization -------------------------------------------------------
    def _load_bundle(self, workdir) -> dict:
        path = Path(workdir) / "repo" / self._bundle_rel()
        if not path.exists():
            raise RuntimeError(f"STIX bundle missing: {path}")
        if path.stat().st_size > _MAX_BUNDLE_BYTES:
            raise RuntimeError("STIX bundle exceeds size budget")
        with path.open("r", encoding="utf-8", errors="replace") as fh:
            return json.load(fh)

    @staticmethod
    def _attack_ref(obj: dict) -> tuple[str | None, str | None]:
        """Return (attack_id, url) from an object's mitre-attack external ref."""
        for ref in obj.get("external_references", []) or []:
            if ref.get("source_name") == "mitre-attack":
                return ref.get("external_id"), ref.get("url")
        return None, None

    def normalize(self, acquired, workdir) -> list[NormalizedDoc]:
        ref = acquired
        bundle = self._load_bundle(workdir)
        objects = bundle.get("objects", []) if isinstance(bundle, dict) else []

        by_id: dict[str, dict] = {}
        techniques: list[dict] = []
        mitigations: dict[str, dict] = {}
        data_components: dict[str, dict] = {}
        groups: dict[str, dict] = {}
        software: dict[str, dict] = {}
        relationships: list[dict] = []

        for o in objects:
            if not isinstance(o, dict):
                continue
            oid = o.get("id")
            if oid:
                by_id[oid] = o
            otype = o.get("type")
            deprecated = o.get("x_mitre_deprecated") or o.get("revoked")
            if otype == "attack-pattern" and not deprecated:
                techniques.append(o)
            elif otype == "course-of-action" and not deprecated:
                mitigations[oid] = o
            elif otype == "x-mitre-data-component":
                data_components[oid] = o
            elif otype == "intrusion-set" and not deprecated:
                groups[oid] = o
            elif otype in ("malware", "tool") and not deprecated:
                software[oid] = o
            elif otype == "relationship":
                relationships.append(o)

        # Build reverse indexes: technique_id -> [related objects]
        mitig_for: dict[str, list[dict]] = {}
        detect_for: dict[str, list[dict]] = {}
        used_by: dict[str, list[dict]] = {}
        parent_of: dict[str, str] = {}
        for rel in relationships:
            rtype = rel.get("relationship_type")
            src = rel.get("source_ref")
            tgt = rel.get("target_ref")
            if not src or not tgt:
                continue
            if rtype == "mitigates" and src in mitigations:
                mitig_for.setdefault(tgt, []).append(mitigations[src])
            elif rtype == "detects" and src in data_components:
                detect_for.setdefault(tgt, []).append(data_components[src])
            elif rtype == "uses" and tgt and (src in groups or src in software):
                used_by.setdefault(tgt, []).append(by_id.get(src, {}))
            elif rtype == "subtechnique-of":
                parent_of[src] = tgt

        max_files = self.profile.max_files or config.KNOWLEDGE_CONNECTOR_MAX_FILES
        total_budget = config.KNOWLEDGE_CONNECTOR_MAX_TOTAL_BYTES

        # Deterministic ordering by ATT&CK ID.
        def _tid(t: dict) -> str:
            aid, _ = self._attack_ref(t)
            return aid or t.get("name", "")

        docs: list[NormalizedDoc] = []
        total = 0
        for tech in sorted(techniques, key=_tid):
            if len(docs) >= max_files or total >= total_budget:
                break
            aid, url = self._attack_ref(tech)
            if not aid:
                continue
            content = self._render_technique(
                tech, aid, url, mitig_for.get(tech["id"], []),
                detect_for.get(tech["id"], []), used_by.get(tech["id"], []),
                parent_of.get(tech["id"]), by_id)
            clean, findings = injection_scan.neutralize(content)
            name = tech.get("name", aid)
            title = f"{aid} — {name}"
            docs.append(NormalizedDoc(
                rel_path=f"techniques/{aid}.md",
                title=title,
                section=name,
                heading_path=(title,),
                content=clean,
                source_url=url or self.profile.upstream_url,
                source_path=f"{aid}",
                injection=findings,
            ))
            total += len(clean)
        return docs

    def _render_technique(self, tech, aid, url, mitigs, detects, uses,
                          parent_ref, by_id) -> str:
        name = tech.get("name", aid)
        lines: list[str] = [f"# {aid} — {name}", ""]

        tactics = [p.get("phase_name") for p in tech.get("kill_chain_phases", [])
                   if p.get("kill_chain_name") == "mitre-attack" and p.get("phase_name")]
        platforms = tech.get("x_mitre_platforms", []) or []
        meta: list[str] = []
        if tactics:
            meta.append(f"**Tactics:** {', '.join(sorted(set(tactics)))}")
        if platforms:
            meta.append(f"**Platforms:** {', '.join(platforms)}")
        if tech.get("x_mitre_is_subtechnique") and parent_ref:
            parent = by_id.get(parent_ref, {})
            paid, _ = self._attack_ref(parent)
            if paid:
                meta.append(f"**Sub-technique of:** {paid} — {parent.get('name', '')}")
        data_sources = tech.get("x_mitre_data_sources", []) or []
        if data_sources:
            meta.append(f"**Data sources:** {', '.join(data_sources)}")
        if meta:
            lines.append("  \n".join(meta))
            lines.append("")

        desc = (tech.get("description") or "").strip()
        if desc:
            lines += [desc, ""]

        detection = (tech.get("x_mitre_detection") or "").strip()
        if detection:
            lines += ["## Detection", detection, ""]

        if detects:
            lines.append("## Detection data components")
            for dc in sorted(detects, key=lambda d: d.get("name", "")):
                src_name = ""
                # data component's parent data source, if resolvable
                lines.append(f"- {dc.get('name', 'component')}"
                             + (f" — {src_name}" if src_name else ""))
            lines.append("")

        if mitigs:
            lines.append("## Mitigations")
            for m in sorted(mitigs, key=lambda x: self._attack_ref(x)[0] or ""):
                mid, _ = self._attack_ref(m)
                mdesc = (m.get("description") or "").strip().splitlines()
                first = mdesc[0] if mdesc else ""
                lines.append(f"- **{mid} — {m.get('name', '')}**: {first}")
            lines.append("")

        if uses:
            lines.append("## Observed use by groups / software")
            seen: set[str] = set()
            for u in uses:
                uid, _ = self._attack_ref(u)
                label = f"{uid} " if uid else ""
                entry = f"- {label}{u.get('name', '')} ({u.get('type', '')})"
                if entry not in seen:
                    seen.add(entry)
                    lines.append(entry)
            lines.append("")

        return "\n".join(lines).strip() + "\n"
