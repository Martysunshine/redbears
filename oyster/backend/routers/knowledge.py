"""Knowledge Pack API — curated, global, source-attributed cybersecurity knowledge.

Packs are global built-in resources (not project-scoped). Installing a pack
indexes its curated docs into the dedicated knowledge collection (vector) and a
SQLite provenance table (lexical + citation resolution). Retrieval is hybrid and
searches only installed **and enabled** packs. Answers are grounded in retrieved
chunks with source URLs; every citation resolves to an inspectable source
passage. Retrieved content is untrusted DATA, never instructions.
"""

from __future__ import annotations

import hashlib
import time
from collections import defaultdict, deque

from fastapi import APIRouter, HTTPException, Request

import log_config
from models.schemas import (KnowledgeAskRequest, KnowledgeEnableRequest,
                            KnowledgeRiskRequest, KnowledgeSearchRequest,
                            SecurityIntelligenceAskRequest)
from services.knowledge import metrics as knowledge_metrics
from services.knowledge import pack_service, registries, registry
from services.knowledge import security_answer, security_router
from services.knowledge.connectors import service as connector_service

router = APIRouter(tags=["knowledge"])

# Per-caller sliding-window limit on the LLM-backed ask endpoints, so even an
# authenticated caller (or a leaked token) cannot drive unbounded inference or
# paid rerank calls. Caller key = hash of the bearer token, else client IP.
# In-memory, per process — a multi-worker deployment needs a shared store.
_ask_hits: dict[str, deque] = defaultdict(deque)


def _rate_limit_ask(request: Request) -> None:
    import config
    limit = config.KNOWLEDGE_STREAM_RATE_PER_MIN
    if limit <= 0:
        return
    authz = request.headers.get("authorization", "")
    who = hashlib.sha256(authz.encode()).hexdigest()[:16] if authz else (
        request.client.host if request.client else "unknown")
    now, q = time.monotonic(), _ask_hits[who]
    while q and now - q[0] > 60:
        q.popleft()
    if len(q) >= limit:
        raise HTTPException(status_code=429, detail="Too many requests; slow down",
                            headers={"Retry-After": str(max(1, int(60 - (now - q[0]))))})
    q.append(now)


# ---------------------------------------------------------------------------
# Metrics — factual, verified statistics for the active knowledge base.
# Read straight from the live store; never a hard-coded 100,000.
# ---------------------------------------------------------------------------

@router.get("/knowledge/metrics")
async def knowledge_metrics_endpoint():
    """Canonical factual metrics of the active knowledge base (unique searchable
    chunks, sources, index/attribution coverage, latest retrieval-eval score)."""
    import asyncio
    return await asyncio.to_thread(knowledge_metrics.compute)


@router.get("/knowledge/metrics/public")
async def knowledge_public_statement():
    """Display-ready headline. The 100k marketing sentence is emitted ONLY when
    the live store actually satisfies the threshold (else it is null)."""
    import asyncio
    return await asyncio.to_thread(knowledge_metrics.public_statement)


# ---------------------------------------------------------------------------
# Packs
# ---------------------------------------------------------------------------

@router.get("/knowledge/packs")
async def list_packs():
    """Available packs merged with install + enable state (version-aware)."""
    packs = pack_service.list_with_status()
    return {
        "packs": packs,
        "total": len(packs),
        "installed": sum(1 for p in packs if p["installed"]),
        "enabled": sum(1 for p in packs if p.get("enabled")),
    }


@router.get("/knowledge/packs/{pack_id}")
async def get_pack(pack_id: str):
    pack = registry.get_pack(pack_id)
    if pack is None:
        raise HTTPException(status_code=404, detail=f"Unknown pack '{pack_id}'")
    status = next((p for p in pack_service.list_with_status() if p["id"] == pack_id), {})
    return {"pack": pack, "installed": pack_service.is_installed(pack_id),
            "enabled": pack_service.is_enabled(pack_id), "status": status}


@router.get("/knowledge/packs/{pack_id}/export")
async def export_pack(pack_id: str):
    """Export a pack's machine-readable metadata (not the copyrighted content)."""
    pack = registry.get_pack(pack_id)
    if pack is None:
        raise HTTPException(status_code=404, detail=f"Unknown pack '{pack_id}'")
    meta = {k: v for k, v in pack.items() if k != "docs"}
    meta["docs"] = [{"file": d["file"], "source_title": d.get("source_title"),
                     "source_url": d.get("source_url")} for d in pack["docs"]]
    return {"pack_metadata": meta}


@router.post("/knowledge/packs/{pack_id}/install")
async def install_pack(pack_id: str):
    result = await pack_service.install(pack_id)
    if not result.get("ok"):
        raise HTTPException(status_code=400, detail=result.get("error", "Install failed"))
    return result


@router.delete("/knowledge/packs/{pack_id}")
async def uninstall_pack(pack_id: str):
    ok = await pack_service.uninstall(pack_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Pack not installed")
    return {"ok": True, "pack_id": pack_id, "uninstalled": True}


@router.post("/knowledge/packs/{pack_id}/enabled")
async def set_pack_enabled(pack_id: str, request: KnowledgeEnableRequest):
    ok = pack_service.set_enabled(pack_id, request.enabled)
    if not ok:
        raise HTTPException(status_code=404, detail="Pack not installed")
    return {"ok": True, "pack_id": pack_id, "enabled": request.enabled}


@router.get("/knowledge/packs/{pack_id}/update-check")
async def update_check(pack_id: str):
    return pack_service.check_update(pack_id)


@router.get("/knowledge/packs/{pack_id}/history")
async def pack_history(pack_id: str):
    return {"pack_id": pack_id, "history": pack_service.history(pack_id)}


# ---------------------------------------------------------------------------
# Search / ask / citation resolution
# ---------------------------------------------------------------------------

@router.post("/knowledge/search")
async def search_knowledge(request: KnowledgeSearchRequest):
    results = await pack_service.search(request.query, top_k=request.top_k,
                                        pack_id=request.pack_id, filters=request.filters)
    return {"results": results, "total": len(results), "query": request.query}


@router.post("/knowledge/ask")
async def ask_knowledge(request: KnowledgeAskRequest, http_request: Request):
    _rate_limit_ask(http_request)
    return await pack_service.ask(request.question, model=request.model,
                                  top_k=request.top_k, pack_id=request.pack_id,
                                  filters=request.filters, history=request.history,
                                  rerank=request.rerank)


@router.post("/knowledge/ask/stream")
async def ask_knowledge_stream(request: KnowledgeAskRequest, http_request: Request):
    """Streaming counterpart of /knowledge/ask (NDJSON, one JSON object per line):

      {"type":"meta","citations":[...],"rerank":{...}|null,"model":key,"ollama_model":name,"grounded":bool}
      {"type":"token","text":"..."}              (repeated)
      {"type":"done","answer":final,"quality_flags":[...],"ttft_ms":n,"total_ms":n}
      {"type":"error","detail":"..."}            (instead of done, on failure)

    Evidence (and its rerank status) is sent BEFORE the first token so the UI can
    show sources while the answer streams. ``done.answer`` is the same text after
    citation-marker repair — markers pointing past the real sources are removed.
    """
    import json

    import config
    from fastapi.responses import StreamingResponse
    _rate_limit_ask(http_request)
    from services import ollama_service, output_validator as ov, rag_service

    def frame(obj: dict) -> str:
        return json.dumps(obj, ensure_ascii=False) + "\n"

    async def gen():
        t0 = time.perf_counter()
        resolved = config.resolve_model(request.model)
        try:
            citations, rerank_info = await pack_service.gather_evidence(
                request.question, request.top_k, request.pack_id, request.filters, request.rerank)
            yield frame({"type": "meta", "citations": citations, "rerank": rerank_info,
                         "model": request.model, "ollama_model": resolved,
                         "grounded": bool(citations),
                         "retrieval_ms": int((time.perf_counter() - t0) * 1000)})
            if not citations:
                yield frame({"type": "done", "answer": pack_service.NO_PACKS_MESSAGE,
                             "quality_flags": [], "ttft_ms": None,
                             "total_ms": int((time.perf_counter() - t0) * 1000)})
                return
            messages = rag_service.build_knowledge_messages(request.question, citations,
                                                            history=request.history)
            text, ttft = "", None
            async for tok in ollama_service.stream_chat(messages, resolved):
                if ttft is None:
                    ttft = int((time.perf_counter() - t0) * 1000)
                text += tok
                yield frame({"type": "token", "text": tok})
            final = pack_service._redact(ov.repair_citation_markers(text, len(citations)))
            res = ov.validate(final, citations=citations, check_citation_markers=True)
            yield frame({"type": "done", "answer": final, "quality_flags": res.flag_codes(),
                         "ttft_ms": ttft, "total_ms": int((time.perf_counter() - t0) * 1000)})
        except Exception as exc:  # surfaced in-band: the HTTP status is already 200
            detail = getattr(exc, "detail", None) or f"{type(exc).__name__}: {exc}"
            yield frame({"type": "error", "detail": str(detail)})

    return StreamingResponse(gen(), media_type="application/x-ndjson")


@router.post("/knowledge/intelligence/ask")
async def ask_security_intelligence(request: SecurityIntelligenceAskRequest):
    """Deterministic pre-LLM-routed security question answering (Part 3/5):
    exact CVE/CWE/CAPEC/ATT&CK/D3FEND identifiers resolve to a real DB lookup;
    detection/mitigation/incident-response/cloud/vulnerability-filter questions
    route to the packs/tables that actually answer them; everything else falls
    back to hybrid retrieval. Returns the 7-part grounded answer format."""
    return await security_answer.answer(request.question, model=request.model,
                                        top_k=request.top_k)


@router.get("/knowledge/intelligence/classify")
async def classify_security_question(question: str):
    """Expose the router's classification decision on its own, for the UI to
    show which route/identifiers were detected without running retrieval."""
    return security_router.classify(question)


@router.get("/knowledge/citation/{chunk_id:path}")
async def resolve_citation(chunk_id: str):
    """Source inspector — full passage + provenance + external link for a citation."""
    payload = pack_service.resolve_citation(chunk_id)
    if payload is None:
        raise HTTPException(status_code=404, detail="Citation not found")
    return payload


# ---------------------------------------------------------------------------
# Registries (disabled-by-default definitions) + risk classifier
# ---------------------------------------------------------------------------

@router.get("/knowledge/registries")
async def list_registries():
    return registries.summary()


@router.get("/knowledge/registries/{name}")
async def get_registry(name: str):
    loaders = {
        "datasets": registries.datasets,
        "labs": registries.labs,
        "secondary_sources": registries.secondary_sources,
        "adversarial_fixtures": registries.adversarial_fixtures,
    }
    fn = loaders.get(name)
    if fn is None:
        raise HTTPException(status_code=404, detail=f"Unknown registry '{name}'")
    return fn()


@router.post("/knowledge/classify-risk")
async def classify_risk(request: KnowledgeRiskRequest):
    """Classify content for payload/exploit risk (read-only; gates tool use)."""
    return registries.classify_content_risk(request.text)


# ---------------------------------------------------------------------------
# Source Connectors (real upstream ingestion — licence/provenance gated)
# ---------------------------------------------------------------------------

@router.get("/knowledge/connectors")
async def list_connectors():
    """All declared source connectors with health, licence disposition, and
    install state. Nothing is fetched here."""
    conns = connector_service.list_connectors()
    return {
        "connectors": conns,
        "total": len(conns),
        "installable": sum(1 for c in conns if c["can_store_local"]),
        "licence_blocked": sum(1 for c in conns if not c["can_store_local"]),
    }


@router.get("/knowledge/connectors/{connector_id}")
async def get_connector(connector_id: str):
    view = connector_service.get_connector_view(connector_id)
    if view is None:
        raise HTTPException(status_code=404, detail=f"Unknown connector '{connector_id}'")
    return view


@router.post("/knowledge/connectors/{connector_id}/preview")
async def preview_connector(connector_id: str):
    """Acquire + normalize the upstream and report counts/samples WITHOUT
    installing. Licence-blocked and unavailable connectors return ok=False."""
    result = connector_service.preview(connector_id)
    if result.get("error") and "Unknown connector" in str(result.get("error")):
        raise HTTPException(status_code=404, detail=result["error"])
    return result


@router.post("/knowledge/connectors/{connector_id}/install")
async def install_connector(connector_id: str):
    """Run the full ingestion pipeline and materialize + install a pack.
    Blocked (licence) → ok=False, blocked=True. Never raises on a blocked import."""
    result = await connector_service.install(connector_id)
    if result.get("error") and "Unknown connector" in str(result.get("error")):
        raise HTTPException(status_code=404, detail=result["error"])
    return result


@router.get("/knowledge/connectors/{connector_id}/update-check")
async def connector_update_check(connector_id: str):
    result = connector_service.update_check(connector_id)
    if not result.get("ok") and "Unknown connector" in str(result.get("error", "")):
        raise HTTPException(status_code=404, detail=result["error"])
    return result


@router.get("/knowledge/connectors/{connector_id}/jobs")
async def connector_jobs(connector_id: str):
    return {"connector_id": connector_id, "jobs": connector_service.import_jobs(connector_id)}


@router.get("/knowledge/import-jobs/{job_id}")
async def import_job_status(job_id: str):
    job = connector_service.job_status(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Import job not found")
    return job


# ---------------------------------------------------------------------------
# Cross-source knowledge graph (Phase 9)
# ---------------------------------------------------------------------------

@router.post("/knowledge/graph/rebuild")
async def rebuild_graph():
    import asyncio
    from services.knowledge.graph import builder
    stats = await asyncio.to_thread(builder.build)
    log_config.audit("knowledge_graph_rebuild", {
        "techniques": stats.get("techniques"),
        "packs": stats.get("packs"),
    })
    return {"ok": True, "stats": stats}


@router.get("/knowledge/graph/stats")
async def graph_stats():
    from services.knowledge.graph import query
    return query.stats()


@router.get("/knowledge/graph/technique/{technique_id}")
async def graph_technique(technique_id: str):
    from services.knowledge.graph import query
    cov = query.technique_coverage(technique_id)
    if cov is None:
        raise HTTPException(status_code=404,
                            detail=f"Technique {technique_id} not present in the graph "
                                   "(rebuild the graph, or the id is not covered by any source).")
    return cov


@router.get("/knowledge/graph/inconsistencies")
async def graph_inconsistencies(kind: str | None = None, limit: int = 500):
    from services.knowledge.graph import query
    items = query.inconsistencies(kind, limit)
    return {"count": len(items), "kind": kind, "inconsistencies": items}
