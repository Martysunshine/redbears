"""Source-connector orchestration: preview / install / update-check.

Pipeline for an install::

    profile → licence gate → connector health → version discovery → acquire
    (shallow clone) → normalize (+ injection neutralize) → materialize an on-disk
    Knowledge Pack (atomic dir swap) → pack_service.install (chunk/embed/
    provenance/citation) → import-job record → cleanup workdir.

A failed import never touches the currently-installed pack: materialization
builds into a staging dir and atomically swaps, restoring the previous pack on
any error. Imported content is neutralized (bidi/zero-width stripped) and
injection-scanned before it is ever written; it is stored as inert DATA.
"""

from __future__ import annotations

import json
import shutil
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

import config
import log_config

from .. import pack_service, store
from . import injection_scan, licensing, profiles
from .base import ConnectorProfile, NormalizedDoc


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_rel(rel: str) -> str | None:
    """Reject path-traversal / absolute paths in a materialized file name."""
    p = Path(rel)
    if p.is_absolute() or ".." in p.parts or rel.startswith("/"):
        return None
    return p.as_posix()


_SOURCE_HEADER_PREFIX = "<!-- source: "
_SOURCE_HEADER_SUFFIX = " -->\n"


def _split_header(text: str) -> tuple[str | None, str]:
    """``(header_line, body)`` for a materialized doc, or ``(None, text)`` if
    it doesn't start with our generated source-attribution comment."""
    if text.startswith(_SOURCE_HEADER_PREFIX):
        end = text.find("\n")
        if end != -1:
            return text[: end + 1], text[end + 1 :]
    return None, text


def _stable_materialized_text(existing_dest: Path, new_source_url: str, new_content: str) -> str:
    """Byte-identical output across re-syncs when the upstream document itself
    hasn't changed.

    A naive re-materialization always writes the CURRENT sync's resolved
    commit ref into the ``<!-- source: URL -->`` header, so every file in a
    pack whose repo advanced by even one unrelated commit gets a full diff —
    thousands of files, one line each, zero actual content change. Since git
    blob URLs pinned to an older commit remain valid indefinitely, there is no
    reason to touch the header when the document body is unchanged: reuse the
    previous file verbatim so the diff for that document is genuinely empty.
    """
    header = f"{_SOURCE_HEADER_PREFIX}{new_source_url}{_SOURCE_HEADER_SUFFIX}"
    if existing_dest.exists():
        try:
            old_text = existing_dest.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            old_text = None
        if old_text is not None:
            _, old_body = _split_header(old_text)
            if old_body == new_content:
                return old_text
    return header + new_content


# ---------------------------------------------------------------------------
# Listing / health
# ---------------------------------------------------------------------------

def list_connectors() -> list[dict]:
    installed = store.pack_meta_map()
    jobs_by_conn: dict[str, dict] = {}
    for j in store.list_import_jobs():
        jobs_by_conn.setdefault(j["connector_id"], j)  # most recent (list is DESC)

    out = []
    for p in profiles.all_profiles():
        connector = profiles.build_connector(p) if _impl_available(p) else None
        health = connector.health() if connector else {"available": False,
                                                        "reason": "source type not yet implemented"}
        lic = licensing.evaluate(p)
        pack_id = p.resolved_pack_id()
        inst = installed.get(pack_id)
        last_job = jobs_by_conn.get(p.id)
        out.append({
            **p.to_dict(),
            "health": health,
            "licence_evaluation": lic,
            "can_store_local": lic["allowed"],
            "installed": inst is not None,
            "installed_version": inst["version"] if inst else None,
            "installed_chunks": inst["chunk_count"] if inst else 0,
            "last_import": last_job,
        })
    return out


def _impl_available(profile: ConnectorProfile) -> bool:
    try:
        profiles.build_connector(profile)
        return True
    except NotImplementedError:
        return False


def get_connector_view(connector_id: str) -> dict | None:
    for c in list_connectors():
        if c["id"] == connector_id:
            return c
    return None


# ---------------------------------------------------------------------------
# Preview (acquire + normalize, no install)
# ---------------------------------------------------------------------------

def preview(connector_id: str) -> dict:
    profile = profiles.get_profile(connector_id)
    if profile is None:
        return {"ok": False, "error": f"Unknown connector '{connector_id}'"}
    lic = licensing.evaluate(profile)
    if not lic["allowed"]:
        return {"ok": False, "blocked": True, "reason": "licence",
                "licence_evaluation": lic, "connector_id": connector_id}
    try:
        connector = profiles.build_connector(profile)
    except NotImplementedError as e:
        return {"ok": False, "error": str(e), "connector_id": connector_id}
    health = connector.health()
    if not health["available"]:
        return {"ok": False, "error": health.get("reason", "connector unavailable"),
                "connector_id": connector_id}

    work = Path(tempfile.mkdtemp(prefix="oyster_kimport_", dir=_workroot()))
    try:
        ref = connector.acquire(str(work))
        docs = connector.normalize(ref, str(work))
        findings = sum(len(d.injection) for d in docs)
        return {
            "ok": True, "connector_id": connector_id, "pack_id": profile.resolved_pack_id(),
            "ref": ref, "doc_count": len(docs),
            "sample_titles": [d.title for d in docs[:12]],
            "injection_findings": findings,
            "licence_evaluation": lic,
        }
    except Exception as e:  # noqa: BLE001 — surface acquisition/parse failures
        return {"ok": False, "error": f"{type(e).__name__}: {e}", "connector_id": connector_id}
    finally:
        shutil.rmtree(work, ignore_errors=True)


# ---------------------------------------------------------------------------
# Install (full pipeline)
# ---------------------------------------------------------------------------

def _workroot() -> Path:
    root = config.KNOWLEDGE_CONNECTOR_WORKDIR
    root.mkdir(parents=True, exist_ok=True)
    return root


def _materialize(profile: ConnectorProfile, ref: str, docs: list[NormalizedDoc]) -> tuple[Path, dict]:
    """Write normalized docs + a generated manifest into the packs dir atomically.

    Returns ``(final_pack_dir, manifest)``. Restores the previous pack on failure.
    """
    pack_id = profile.resolved_pack_id()
    packs_dir = config.KNOWLEDGE_PACKS_DIR
    packs_dir.mkdir(parents=True, exist_ok=True)
    final = packs_dir / pack_id
    staging = packs_dir / f".{pack_id}.incoming-{uuid.uuid4().hex[:8]}"
    backup = packs_dir / f".{pack_id}.bak-{uuid.uuid4().hex[:8]}"

    version = (ref or profile.default_ref)[:12]
    doc_entries = []
    try:
        staging.mkdir(parents=True, exist_ok=True)
        for d in docs:
            rel = _safe_rel(d.rel_path)
            if rel is None:
                continue
            # ensure the materialized name ends in .md so the registry treats it as a doc
            fname = rel if rel.lower().endswith(".md") else rel + ".md"
            dest = staging / fname
            dest.parent.mkdir(parents=True, exist_ok=True)
            source_url = d.source_url or profile.upstream_url
            text = _stable_materialized_text(final / fname, source_url, d.content)
            dest.write_text(text, encoding="utf-8")
            doc_entries.append({
                "file": fname,
                "source_title": d.title,
                "source_url": d.source_url or profile.upstream_url,
                "section": d.section,
            })

        manifest = {
            "id": pack_id,
            "name": profile.name,
            "version": version,
            "title": profile.display_name,
            "domain": profile.domain,
            "security_domain": profile.security_domain,
            "description": f"Imported from {profile.upstream_url} at {version}. "
                           f"{len(doc_entries)} documents.",
            "authority": profile.authority,
            "publisher": profile.publisher,
            "trust_level": profile.trust_level,
            "licence": profile.licence,
            "attribution": profile.attribution,
            "tags": list(profile.tags),
            "applicable_tools": list(profile.applicable_tools),
            "applicable_platforms": list(profile.applicable_platforms),
            "risk_classification": profile.risk_classification,
            "active_execution_possible": profile.active_execution_possible,
            "freshness_policy": profile.freshness_policy,
            "retrieved_at": _ts()[:10],
            "last_reviewed_at": _ts()[:10],
            "origin": "connector",
            "connector_id": profile.id,
            "upstream_commit": ref,
            "source_urls": [profile.upstream_url] + ([profile.repo_url] if profile.repo_url else []),
            "docs": doc_entries,
        }
        (staging / "pack.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

        # atomic swap
        if final.exists():
            final.rename(backup)
        staging.rename(final)
        if backup.exists():
            shutil.rmtree(backup, ignore_errors=True)
        return final, manifest
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        if backup.exists() and not final.exists():
            backup.rename(final)  # restore previous pack
        raise


async def install(connector_id: str) -> dict:
    profile = profiles.get_profile(connector_id)
    if profile is None:
        return {"ok": False, "error": f"Unknown connector '{connector_id}'"}

    job_id = f"job-{connector_id}-{uuid.uuid4().hex[:8]}"
    store.start_import_job(job_id, connector_id)

    lic = licensing.evaluate(profile)
    if not lic["allowed"]:
        store.finish_import_job(job_id, "blocked", licence=profile.licence,
                                disposition=lic["disposition"],
                                error="licence disposition forbids local storage",
                                detail="; ".join(lic["reasons"]))
        log_config.audit("knowledge_import_blocked",
                         {"connector": connector_id, "reason": "licence",
                          "disposition": lic["disposition"]})
        return {"ok": False, "blocked": True, "reason": "licence",
                "licence_evaluation": lic, "job_id": job_id}

    try:
        connector = profiles.build_connector(profile)
    except NotImplementedError as e:
        store.finish_import_job(job_id, "failed", error=str(e))
        return {"ok": False, "error": str(e), "job_id": job_id}

    health = connector.health()
    if not health["available"]:
        store.finish_import_job(job_id, "failed", error=health.get("reason", "unavailable"))
        return {"ok": False, "error": health.get("reason", "connector unavailable"),
                "job_id": job_id}

    work = Path(tempfile.mkdtemp(prefix="oyster_kimport_", dir=_workroot()))
    try:
        ref = connector.acquire(str(work))
        docs = connector.normalize(ref, str(work))
        if not docs:
            store.finish_import_job(job_id, "failed", ref=ref,
                                    error="no documents matched include globs")
            return {"ok": False, "error": "no documents matched", "job_id": job_id, "ref": ref}

        findings = sum(len(d.injection) for d in docs)
        _final, manifest = _materialize(profile, ref, docs)

        # flow through the existing verified install pipeline
        result = await pack_service.install(profile.resolved_pack_id())
        if not result.get("ok"):
            store.finish_import_job(job_id, "failed", ref=ref, error=result.get("error"))
            return {"ok": False, "error": result.get("error"), "job_id": job_id}

        store.finish_import_job(
            job_id, "succeeded", pack_id=profile.resolved_pack_id(), ref=ref,
            doc_count=result["docs"], chunk_count=result["chunks"],
            injection_findings=findings, licence=profile.licence,
            disposition=lic["disposition"],
            detail=f"{result['docs']} docs / {result['chunks']} chunks from {ref[:12]}",
        )
        log_config.audit("knowledge_import_succeeded",
                         {"connector": connector_id, "pack_id": profile.resolved_pack_id(),
                          "ref": ref[:12], "docs": result["docs"], "chunks": result["chunks"],
                          "injection_findings": findings})
        return {
            "ok": True, "connector_id": connector_id, "job_id": job_id,
            "pack_id": profile.resolved_pack_id(), "ref": ref,
            "version": manifest["version"], "docs": result["docs"],
            "chunks": result["chunks"], "injection_findings": findings,
            "licence": profile.licence, "attribution": profile.attribution,
            "reused_docs": result.get("reused_docs", 0),
        }
    except Exception as e:  # noqa: BLE001
        store.finish_import_job(job_id, "failed", error=f"{type(e).__name__}: {e}")
        log_config.audit("knowledge_import_failed",
                         {"connector": connector_id, "error": str(e)[:200]})
        return {"ok": False, "error": f"{type(e).__name__}: {e}", "job_id": job_id}
    finally:
        shutil.rmtree(work, ignore_errors=True)


# ---------------------------------------------------------------------------
# Update check (upstream drift)
# ---------------------------------------------------------------------------

def update_check(connector_id: str) -> dict:
    profile = profiles.get_profile(connector_id)
    if profile is None:
        return {"ok": False, "error": f"Unknown connector '{connector_id}'"}
    try:
        connector = profiles.build_connector(profile)
    except NotImplementedError as e:
        return {"ok": False, "error": str(e)}
    latest = connector.discover_version()
    jobs = store.list_import_jobs(connector_id)
    last_ok = next((j for j in jobs if j["status"] == "succeeded"), None)
    installed_ref = last_ok["ref"] if last_ok else None
    if latest is None:
        return {"ok": True, "connector_id": connector_id, "status": "unknown-upstream",
                "installed_ref": installed_ref, "latest_ref": None}
    if installed_ref is None:
        return {"ok": True, "connector_id": connector_id, "status": "not-installed",
                "latest_ref": latest}
    changed = installed_ref != latest
    return {"ok": True, "connector_id": connector_id,
            "status": "update-available" if changed else "current",
            "installed_ref": installed_ref, "latest_ref": latest}


def import_jobs(connector_id: str | None = None) -> list[dict]:
    return store.list_import_jobs(connector_id)


def job_status(job_id: str) -> dict | None:
    return store.get_import_job(job_id)
