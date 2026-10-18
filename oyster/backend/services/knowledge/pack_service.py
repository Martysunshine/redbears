"""Install / enable / update / search Knowledge Packs and answer from them.

Install = read the pack's curated Markdown docs → chunk + embed into the
dedicated knowledge Chroma collection AND write per-chunk provenance to SQLite
(for lexical search + citation resolution) → record full install metadata
(checksum, licence, risk, freshness, enabled flag). Idempotent.

A pack can be independently installed / enabled / disabled / searched / updated
/ removed without touching project data. Retrieval is hybrid (vector + lexical)
and only searches installed **and enabled** packs. The LLM reasons over the
retrieved chunks; retrieved text is untrusted DATA (never instructions) and
every substantive answer is grounded in cited sources.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path

import config
import log_config
from services import ollama_service, rag_service

from . import registry, retrieval, store

try:  # defence-in-depth: strip any secret-shaped strings from model context/logs
    from services.media.redact import redact as _redact
except Exception:  # pragma: no cover - media stack optional
    def _redact(text: str) -> str:  # type: ignore
        return text


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat()


def init_db() -> None:
    store.init_db()


# ---------------------------------------------------------------------------
# Install state / listing
# ---------------------------------------------------------------------------

def _installed_map() -> dict[str, dict]:
    return store.pack_meta_map()


def list_with_status() -> list[dict]:
    """Available packs merged with install state + full metadata (version-aware)."""
    installed = _installed_map()
    out = []
    for p in registry.list_packs():
        inst = installed.get(p["id"])
        outdated = bool(inst and inst.get("content_checksum")
                        and inst["content_checksum"] != p["content_checksum"])
        out.append({
            **p,
            "installed": inst is not None,
            "enabled": bool(inst and (inst.get("enabled") in (1, None))) if inst else False,
            "installed_version": inst["version"] if inst else None,
            "installed_checksum": inst.get("content_checksum") if inst else None,
            "outdated": outdated or bool(inst and inst["version"] != p["version"]),
            "update_status": "update-available" if outdated else ("current" if inst else "not-installed"),
            "chunk_count": inst["chunk_count"] if inst else 0,
        })
    return out


def is_installed(pack_id: str) -> bool:
    return pack_id in _installed_map()


def is_enabled(pack_id: str) -> bool:
    row = _installed_map().get(pack_id)
    return bool(row and (row.get("enabled") in (1, None)))


# ---------------------------------------------------------------------------
# Install / uninstall
# ---------------------------------------------------------------------------

async def install(pack_id: str) -> dict:
    pack = registry.get_pack(pack_id)
    if pack is None:
        return {"ok": False, "error": f"Unknown pack '{pack_id}'"}
    if not pack.get("valid"):
        return {"ok": False, "error": pack.get("error", "Pack is invalid or has no docs")}

    prev = _installed_map().get(pack_id)

    # Read what's already indexed BEFORE touching anything, keyed by doc, so a
    # doc whose content is byte-identical to what's already installed can be
    # recognized and left alone. Re-embedding is the expensive part of an
    # install; a re-sync where the upstream ref advanced but a given file's
    # content didn't (the common case for a connector pack) must not pay that
    # cost again for every doc in the pack.
    existing_by_doc: dict[str, list[dict]] = {}
    for row in store.chunks_for_pack(pack_id):
        existing_by_doc.setdefault(row["doc_id"], []).append(row)

    total_chunks = 0
    indexed_docs = 0
    reused_docs = 0
    provenance: list[dict] = []
    seen_doc_ids: set[str] = set()
    for doc in pack["docs"]:
        if not doc["exists"]:
            continue
        try:
            text = Path(doc["path"]).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if not text.strip():
            continue
        doc_id = f"kp::{pack_id}::{doc['file']}"
        seen_doc_ids.add(doc_id)
        doc_risk = doc.get("risk_level") or pack["risk_classification"]

        new_hashes = [hashlib.sha256(c.encode("utf-8")).hexdigest()
                     for c in rag_service._chunk_text(text)]
        old_rows = existing_by_doc.get(doc_id)
        unchanged = old_rows is not None and [r["content_hash"] for r in old_rows] == new_hashes

        if unchanged:
            # Content is exactly what's already indexed — reuse the existing
            # rows verbatim (skips calling the embedding model entirely).
            for r in old_rows:
                entry = {k: r[k] for k in (
                    "id", "doc_id", "document", "source_type", "title", "publisher",
                    "canonical_url", "licence", "trust_level", "risk_level", "domain",
                    "section", "chunk_index", "content_hash", "content")}
                entry["pack_version"] = pack["version"]  # cheap SQL-only refresh
                provenance.append(entry)
            total_chunks += len(old_rows)
            indexed_docs += 1
            reused_docs += 1
            continue

        if old_rows:
            # Content (or chunk count) changed — drop only THIS doc's old
            # vector ids, not the whole pack, before re-embedding it.
            await rag_service.delete_knowledge_chunk_ids_async([r["id"] for r in old_rows])

        records = await rag_service.ingest_knowledge_async(
            pack_id, pack["version"], doc["file"], text,
            source_url=doc.get("source_url"), source_title=doc.get("source_title"),
            domain=pack["domain"], risk_level=doc_risk,
        )
        for rec in records:
            provenance.append({
                "id": rec["id"],
                "pack_version": pack["version"],
                "doc_id": doc_id,
                "document": doc.get("source_title") or doc["file"],
                "source_type": "built_in",
                "title": doc.get("source_title") or pack["title"],
                "publisher": pack.get("publisher") or pack.get("authority"),
                # Every chunk must carry traceable provenance so it can be cited
                # and so the attribution audit passes. An internally-authored
                # pack doc legitimately has no external URL; rather than leave it
                # blank (uncitable) or invent a fake external link, fall back to
                # an honest pack-relative identifier, pack://<pack_id>/<file>.
                "canonical_url": doc.get("source_url") or f"pack://{pack_id}/{doc['file']}",
                "licence": pack.get("licence"),
                "trust_level": pack.get("trust_level"),
                "risk_level": doc_risk,
                "domain": pack["domain"],
                "section": doc.get("section"),
                "chunk_index": rec["chunk_index"],
                "content_hash": hashlib.sha256(rec["content"].encode("utf-8")).hexdigest(),
                "content": rec["content"],
            })
        total_chunks += len(records)
        indexed_docs += 1

    # Docs that existed before but are gone now (removed upstream, or excluded
    # by an updated glob) would otherwise leave their old vectors orphaned in
    # Chroma forever, since nothing above touches a doc_id it doesn't see.
    removed_ids = [r["id"] for doc_id, rows in existing_by_doc.items()
                  if doc_id not in seen_doc_ids for r in rows]
    if removed_ids:
        await rag_service.delete_knowledge_chunk_ids_async(removed_ids)

    store.replace_chunks(pack_id, provenance)

    now = _ts()
    con = store.conn()
    try:
        con.execute(
            "INSERT INTO knowledge_packs (pack_id,version,title,domain,doc_count,chunk_count,"
            "installed_at,updated_at,enabled,content_checksum,licence,attribution,"
            "risk_classification,security_domain,source_urls,trust_level,retrieved_at,"
            "last_reviewed_at,freshness_policy,installation_status,update_status) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?) "
            "ON CONFLICT(pack_id) DO UPDATE SET version=excluded.version,title=excluded.title,"
            "domain=excluded.domain,doc_count=excluded.doc_count,chunk_count=excluded.chunk_count,"
            "updated_at=excluded.updated_at,content_checksum=excluded.content_checksum,"
            "licence=excluded.licence,attribution=excluded.attribution,"
            "risk_classification=excluded.risk_classification,security_domain=excluded.security_domain,"
            "source_urls=excluded.source_urls,trust_level=excluded.trust_level,"
            "retrieved_at=excluded.retrieved_at,last_reviewed_at=excluded.last_reviewed_at,"
            "freshness_policy=excluded.freshness_policy,update_status='current'",
            (
                pack_id, pack["version"], pack["title"], pack["domain"], indexed_docs,
                total_chunks, now, now, 1 if prev is None else prev.get("enabled", 1),
                pack["content_checksum"], pack.get("licence"), pack.get("attribution"),
                pack["risk_classification"], pack.get("security_domain"),
                ",".join(pack.get("source_urls", [])), pack.get("trust_level"),
                pack.get("retrieved_at"), pack.get("last_reviewed_at"),
                pack.get("freshness_policy"), "installed", "current",
            ),
        )
        con.commit()
    finally:
        con.close()

    action = "update" if prev else "install"
    store.record_update(
        pack_id, action,
        from_version=prev.get("version") if prev else None, to_version=pack["version"],
        from_checksum=prev.get("content_checksum") if prev else None,
        to_checksum=pack["content_checksum"],
        note=f"{indexed_docs} docs / {total_chunks} chunks",
    )
    log_config.audit(f"knowledge_pack_{action}", {"pack_id": pack_id, "version": pack["version"],
                                                   "docs": indexed_docs, "chunks": total_chunks,
                                                   "checksum": pack["content_checksum"][:12]})
    return {"ok": True, "pack_id": pack_id, "version": pack["version"],
            "docs": indexed_docs, "chunks": total_chunks, "action": action,
            "content_checksum": pack["content_checksum"], "reused_docs": reused_docs}


async def uninstall(pack_id: str) -> bool:
    if not is_installed(pack_id):
        return False
    await rag_service.delete_pack_async(pack_id)
    store.delete_chunks(pack_id)
    con = store.conn()
    try:
        con.execute("DELETE FROM knowledge_packs WHERE pack_id = ?", (pack_id,))
        con.commit()
    finally:
        con.close()
    store.record_update(pack_id, "uninstall", note="pack removed")
    log_config.audit("knowledge_pack_uninstall", {"pack_id": pack_id})
    return True


# ---------------------------------------------------------------------------
# Enable / disable (retrieval only searches enabled packs)
# ---------------------------------------------------------------------------

def set_enabled(pack_id: str, enabled: bool) -> bool:
    if not is_installed(pack_id):
        return False
    con = store.conn()
    try:
        con.execute("UPDATE knowledge_packs SET enabled = ?, updated_at = ? WHERE pack_id = ?",
                    (1 if enabled else 0, _ts(), pack_id))
        con.commit()
    finally:
        con.close()
    log_config.audit("knowledge_pack_toggle", {"pack_id": pack_id, "enabled": enabled})
    return True


# ---------------------------------------------------------------------------
# Update workflow (manual, checksum-compared, with history)
# ---------------------------------------------------------------------------

def check_update(pack_id: str) -> dict:
    """Compare installed checksum/version against on-disk pack — no changes made."""
    inst = _installed_map().get(pack_id)
    disk = registry.get_pack(pack_id)
    if disk is None:
        return {"pack_id": pack_id, "status": "missing-on-disk"}
    if inst is None:
        return {"pack_id": pack_id, "status": "not-installed",
                "available_version": disk["version"]}
    changed = (inst.get("content_checksum") != disk["content_checksum"]
               or inst["version"] != disk["version"])
    return {
        "pack_id": pack_id,
        "status": "update-available" if changed else "current",
        "installed_version": inst["version"],
        "available_version": disk["version"],
        "installed_checksum": inst.get("content_checksum"),
        "available_checksum": disk["content_checksum"],
    }


def history(pack_id: str) -> list[dict]:
    return store.update_history(pack_id)


# ---------------------------------------------------------------------------
# Search / ask (hybrid retrieval, grounded, cited)
# ---------------------------------------------------------------------------

async def search(query: str, top_k: int = 6, pack_id: str | None = None,
                 filters: dict | None = None) -> list[dict]:
    cites = await retrieval.retrieve(query, top_k=top_k, pack_id=pack_id, filters=filters)
    for c in cites:
        if c.get("chunk"):
            c["chunk"] = _redact(c["chunk"])
    return cites


NO_PACKS_MESSAGE = ("No enabled Knowledge Packs matched (or none are installed). Open the + "
                    "menu → Import Knowledge Pack to install and enable packs, then ask again.")


async def gather_evidence(question: str, top_k: int = 6, pack_id: str | None = None,
                          filters: dict | None = None, rerank: bool = False) -> tuple[list[dict], dict | None]:
    """Retrieve (optionally Nemotron-reranked) and redact the evidence for one
    question. Returns (citations, rerank_info); rerank_info is None when
    reranking was not requested, otherwise says whether it ran or fell back."""
    info = None
    if rerank:
        citations, info = await retrieval.retrieve_reranked(question, top_k=top_k, pack_id=pack_id,
                                                           filters=filters)
    else:
        citations = await retrieval.retrieve(question, top_k=top_k, pack_id=pack_id, filters=filters)
    for c in citations:
        if c.get("chunk"):
            c["chunk"] = _redact(c["chunk"])
    return citations, info


async def ask(question: str, model: str = "oyster-dolphin-v2", top_k: int = 6,
              pack_id: str | None = None, filters: dict | None = None,
              history: list | None = None, rerank: bool = False) -> dict:
    citations, rerank_info = await gather_evidence(question, top_k, pack_id, filters, rerank)
    if not citations:
        return {
            "answer": NO_PACKS_MESSAGE,
            "citations": [], "model": model, "grounded": False, "rerank": rerank_info,
        }
    # Structured /api/chat + output validation (Phase 4 + Phase 6): references
    # in the system message, question as the user turn; regenerate once and fall
    # back to an honest uncertainty message on a hard validation failure.
    from services.artifacts.service import _generate_validated
    messages = rag_service.build_knowledge_messages(question, citations, history=history)
    resolved = config.resolve_model(model)
    answer, quality_flags = await _generate_validated(
        lambda temperature: ollama_service.chat(
            messages, resolved, options={"temperature": temperature} if temperature is not None else None),
        citations=citations)
    answer = _redact(answer)
    log_config.audit("knowledge_ask", {"q": question[:160], "citations": len(citations),
                                        "quality_flags": quality_flags,
                                        "model": model})
    return {"answer": answer, "citations": citations, "model": model, "grounded": True,
            "quality_flags": quality_flags, "rerank": rerank_info}


def resolve_citation(chunk_id: str) -> dict | None:
    payload = retrieval.resolve_citation(chunk_id)
    if payload and payload.get("passage"):
        payload["passage"] = _redact(payload["passage"])
    return payload
