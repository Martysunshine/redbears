"""Artifact ingestion orchestration.

Flow per file:  save → extract text → chunk+embed (project/artifact-scoped RAG)
→ status ready/failed. Never silently fails: every failure is recorded on the
artifact with a human-readable ``error`` and surfaced to the UI.
"""

from __future__ import annotations

import asyncio
import hashlib
import mimetypes
import re
from pathlib import Path

import config
import log_config
from services import ollama_service, rag_service

from services.media import video_probe

from . import extractors, image_extractor, store, video_extractor

_SAFE = re.compile(r"[^A-Za-z0-9._-]+")

# Guard against processing the same artifact twice (survives concurrent polls).
_processing: set[str] = set()
_processing_lock = asyncio.Lock()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _safe_name(name: str) -> str:
    return _SAFE.sub("_", Path(name).name)[:120] or "file"


def _mime(filename: str) -> str:
    return mimetypes.guess_type(filename)[0] or "application/octet-stream"


# ---------------------------------------------------------------------------
# Ingest a single file
# ---------------------------------------------------------------------------

async def ingest_file(project_id: str, filename: str, content: bytes,
                      relative_path: str | None = None,
                      conversation_id: str | None = None) -> dict:
    sha = _sha256(content)
    size = len(content)

    # Dedupe within the project (already-ready identical content).
    existing = store.find_by_sha(project_id, sha)
    if existing:
        return {**existing, "deduped": True}

    rec = store.create(
        project_id, filename, kind="file", mime=_mime(filename), sha256=sha,
        size=size, relative_path=relative_path, conversation_id=conversation_id,
    )
    aid = rec["id"]

    if size > config.MAX_UPLOAD_BYTES:
        store.update(aid, status="failed", extract_status="failed", index_status="skipped",
                     error=f"File too large ({size // (1024*1024)} MB > {config.MAX_UPLOAD_BYTES // (1024*1024)} MB)")
        return store.get(aid)

    if not extractors.is_supported(filename):
        store.update(aid, status="failed", extract_status="failed", index_status="skipped",
                     error=f"Unsupported file type '{Path(filename).suffix}'")
        return store.get(aid)

    # Persist under the active project.
    dest = config.ARTIFACTS_DIR / project_id / f"{aid}_{_safe_name(filename)}"
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_bytes(content)

    # Extract
    try:
        text = await asyncio.to_thread(extractors.extract, dest, filename)
    except extractors.ExtractionError as exc:
        # ExtractionError messages are written for the uploader — no library
        # text, no paths (see extractors.py). The underlying cause is logged.
        store.update(aid, status="failed", extract_status="failed", index_status="skipped", error=str(exc))
        log_config.error("artifact_extract", f"{exc} [{exc.__cause__!r}]",
                         {"artifact": aid, "filename": filename})
        return store.get(aid)
    store.update(aid, extract_status="ok", text=text)

    # Index (chunk + embed, project/artifact scoped)
    try:
        chunks = await rag_service.ingest_async(aid, filename, text, project_id=project_id, artifact_id=aid)
        store.update(aid, status="ready", index_status="indexed", chunk_count=chunks)
    except Exception as exc:  # embedding/model failure — its text can name the model host
        store.update(aid, status="failed", index_status="failed",
                     error="Indexing failed. Please try again later.")
        log_config.error("artifact_index", str(exc), {"artifact": aid})
    return store.get(aid)


# ---------------------------------------------------------------------------
# Note
# ---------------------------------------------------------------------------

async def ingest_note(project_id: str, title: str, content: str,
                      conversation_id: str | None = None) -> dict:
    title = (title or "").strip()
    body = f"# {title}\n\n{content}" if title else (content or "")
    fname = (_safe_name(title) if title else "note") + ".md"
    if not body.strip():
        rec = store.create(project_id, fname, kind="note", mime="text/markdown", sha256="", size=0,
                           conversation_id=conversation_id)
        store.update(rec["id"], status="failed", extract_status="failed", index_status="skipped",
                     error="Note is empty")
        return store.get(rec["id"])
    data = body.encode("utf-8")
    rec = store.create(project_id, fname, kind="note", mime="text/markdown", sha256=_sha256(data),
                       size=len(data), conversation_id=conversation_id)
    aid = rec["id"]
    store.update(aid, extract_status="ok", text=body)
    try:
        chunks = await rag_service.ingest_async(aid, fname, body, project_id=project_id, artifact_id=aid)
        store.update(aid, status="ready", index_status="indexed", chunk_count=chunks)
    except Exception as exc:  # noqa: BLE001
        store.update(aid, status="failed", index_status="failed",
                     error="Indexing failed. Please try again later.")
        log_config.error("artifact_index", str(exc), {"artifact": aid})
    return store.get(aid)


# ---------------------------------------------------------------------------
# Folder (many files, processed independently)
# ---------------------------------------------------------------------------

async def ingest_folder(project_id: str, files: list[tuple[str, bytes]],
                        conversation_id: str | None = None) -> dict:
    artifacts, skipped = [], []
    for rel, content in files:
        name = Path(rel).name
        if not extractors.is_supported(name):
            skipped.append({"path": rel, "reason": "unsupported type"})
            continue
        try:
            rec = await ingest_file(project_id, name, content, relative_path=rel,
                                    conversation_id=conversation_id)
            artifacts.append(rec)
        except Exception as exc:  # never let one bad file abort the folder
            log_config.error("folder_ingest", f"{type(exc).__name__}: {exc}", {"path": rel})
            skipped.append({"path": rel, "reason": "processing failed"})
    ready = [a for a in artifacts if a.get("status") == "ready"]
    return {
        "ingested": len(artifacts),
        "ready": len(ready),
        "failed": len([a for a in artifacts if a.get("status") == "failed"]),
        "skipped": skipped,
        "artifacts": artifacts,
    }


# ---------------------------------------------------------------------------
# Media (image / video) — quick upload, background processing
# ---------------------------------------------------------------------------

def media_kind_for(filename: str) -> str | None:
    ext = Path(filename).suffix.lower()
    if ext in config.IMAGE_EXTENSIONS:
        return "image"
    if ext in config.VIDEO_EXTENSIONS:
        return "video"
    return None


def _thumb_path(project_id: str, aid: str) -> Path:
    return config.ARTIFACTS_DIR / project_id / "thumbnails" / f"{aid}.jpg"


def _frames_dir(project_id: str, aid: str) -> Path:
    return config.ARTIFACTS_DIR / project_id / "frames" / aid


async def ingest_media(project_id: str, filename: str, content: bytes,
                       conversation_id: str | None = None) -> dict:
    """Accept an image/video, persist it, and kick off background processing.

    Returns immediately with a record in ``status='uploaded'`` (processing set to
    'processing') so large videos never block the request. Progress + errors are
    persisted to SQLite, so the UI recovers them after a refresh.
    """
    kind = media_kind_for(filename)
    if kind is None:
        raise ValueError(f"Unsupported media type '{Path(filename).suffix}'")

    sha = _sha256(content)
    size = len(content)
    existing = store.find_by_sha(project_id, sha)
    if existing:
        return {**existing, "deduped": True}

    limit = (config.MAX_IMAGE_SIZE_MB if kind == "image" else config.MAX_VIDEO_SIZE_MB) * 1024 * 1024
    dest = config.ARTIFACTS_DIR / project_id / f"{_id_prefix()}_{_safe_name(filename)}"
    dest.parent.mkdir(parents=True, exist_ok=True)

    rec = store.create(
        project_id, filename, kind=kind, mime=_mime(filename), sha256=sha, size=size,
        conversation_id=conversation_id, original_filename=filename, status="processing",
    )
    aid = rec["id"]
    # storage path uses the real artifact id
    dest = config.ARTIFACTS_DIR / project_id / f"{aid}_{_safe_name(filename)}"
    dest.write_bytes(content)
    store.update(aid, storage_path=str(dest), status="uploaded", extract_status="pending")

    if size > limit:
        store.update(aid, status="failed", extract_status="failed", index_status="skipped",
                     analysis_status="skipped",
                     error=f"File exceeds configured size ({size // (1024*1024)} MB > "
                           f"{limit // (1024*1024)} MB).")
        return store.get(aid)

    # Make the preview available before OCR/vision/transcription. Those jobs
    # can take minutes on a local model; withholding the thumbnail until they
    # finish made an otherwise healthy upload look broken in the demo.
    thumb = _thumb_path(project_id, aid)
    thumb.parent.mkdir(parents=True, exist_ok=True)
    if kind == "image":
        made = await asyncio.to_thread(image_extractor.make_thumbnail, dest, thumb)
    else:
        made = await asyncio.to_thread(video_probe.thumbnail, dest, thumb, 1.0, None)
    if made and thumb.exists():
        store.update(aid, thumbnail_path=str(thumb))

    # Fire-and-forget background processing on the running event loop.
    asyncio.create_task(_process_media(project_id, aid, kind, str(dest), filename))
    return store.get(aid)


def _id_prefix() -> str:
    import uuid
    return str(uuid.uuid4())[:8]


async def _process_media(project_id: str, aid: str, kind: str, path: str, filename: str) -> None:
    async with _processing_lock:
        if aid in _processing:
            return
        _processing.add(aid)
    try:
        thumb = _thumb_path(project_id, aid)
        thumb.parent.mkdir(parents=True, exist_ok=True)
        store.update(aid, status="processing", extract_status="running")

        if kind == "image":
            result = await image_extractor.process(path, filename, str(thumb), project_id=project_id)
        else:
            async def _on_status(state: str) -> None:
                store.update(aid, status=state)
            frames = _frames_dir(project_id, aid)
            result = await video_extractor.process(
                path, filename, str(thumb), str(frames), project_id=project_id, on_status=_on_status,
            )

        store.update(aid, extract_status="ok", analysis_status=result.get("analysis_status", "ok"),
                     text=result["text"], thumbnail_path=str(thumb) if thumb.exists() else None,
                     metadata=result["metadata"], status="indexing")

        # Index media segments (per-chunk content_type + timestamps).
        try:
            chunks = await rag_service.ingest_segments_async(
                aid, filename, result["segments"], project_id=project_id,
                artifact_id=aid, artifact_type=kind,
            )
            store.update(aid, status="ready", index_status="indexed", chunk_count=chunks, error=None)
        except Exception as exc:  # noqa: BLE001
            store.update(aid, status="failed", index_status="failed",
                         error="Indexing failed. Please try again later.")
            log_config.error("artifact_index", str(exc), {"artifact": aid})

    except (image_extractor.ImageError, video_extractor.VideoError) as exc:
        # Both carry sentences written for the uploader; the cause is logged.
        store.update(aid, status="failed", extract_status="failed", index_status="skipped",
                     analysis_status="failed", error=str(exc))
        log_config.error("media_process", f"{exc} [{exc.__cause__!r}]",
                         {"artifact": aid, "kind": kind})
    except Exception as exc:  # pragma: no cover — defensive catch-all
        store.update(aid, status="failed", extract_status="failed", error="Processing failed.")
        log_config.error("media_process", f"{type(exc).__name__}: {exc}",
                         {"artifact": aid, "kind": kind})
    finally:
        async with _processing_lock:
            _processing.discard(aid)


async def reprocess(project_id: str, artifact_id: str) -> dict | None:
    """Re-run processing for a failed/stale media artifact (e.g. after a model pull)."""
    rec = store.get(artifact_id, with_paths=True)
    if not rec or rec["project_id"] != project_id or rec["kind"] not in ("image", "video"):
        return None
    path = rec.get("storage_path")
    if not path or not Path(path).exists():
        return None
    await rag_service.delete_artifact_async(artifact_id)
    store.update(artifact_id, status="processing", error=None, index_status="pending",
                 analysis_status="pending", chunk_count=0)
    asyncio.create_task(_process_media(project_id, artifact_id, rec["kind"], path, rec["filename"]))
    return store.get(artifact_id)


# ---------------------------------------------------------------------------
# Summarize / Ask
# ---------------------------------------------------------------------------

async def summarize(project_id: str, artifact_id: str, model: str = "oyster-dolphin-v2") -> dict | None:
    rec = store.get(artifact_id, with_text=True)
    if not rec or rec["project_id"] != project_id:
        return None
    text = (rec.get("text") or "").strip()
    if not text:
        return {"error": "No extracted text to summarize.", "filename": rec["filename"]}
    excerpt = text[:14000]
    prompt = (
        "You are a document analysis assistant. Summarize the following file clearly and "
        "concisely: main topics, key points, and anything security-relevant.\n\n"
        f"FILE: {rec['filename']}\n\nCONTENT:\n{excerpt}\n\nSummary:"
    )
    summary = await ollama_service.generate(prompt, config.resolve_model(model))
    return {"artifact_id": artifact_id, "filename": rec["filename"], "summary": summary, "model": model}


async def ask(project_id: str, question: str, artifact_id: str | None = None,
              model: str = "oyster-dolphin-v2", top_k: int = 5,
              include_knowledge: bool = True, history: list | None = None) -> dict:
    """Answer from project artifacts, augmented by installed Knowledge Packs.

    Project (uploaded) evidence is retrieved first; when not scoped to a single
    artifact, a few globally-installed Knowledge Pack chunks are blended in so the
    answer draws on curated cybersecurity knowledge too. Knowledge citations carry
    their source URL for attribution. Fully backward compatible: with no packs
    installed this behaves exactly as before.
    """
    # Same application-layer catastrophic-harm boundary as /chat
    # (services/chat_policy.py): the selectable refusal-ablated models do not
    # self-refuse, and Ask never passes through the chat policy otherwise. Only
    # explicit CBRN / mass-casualty / CSAM requests stop here — every other
    # question retrieves and cites exactly as before.
    from services.chat_policy import _catastrophic_boundary, _catastrophic_category
    category = _catastrophic_category(question)
    if category:
        return {"answer": _catastrophic_boundary(category), "citations": [], "model": model}

    # For a follow-up like "how is it exploited?" the subject lives in an earlier
    # turn, so retrieving on the bare words finds generic passages. When there is
    # history AND the question is anaphoric, `build_followup_query` anchors the
    # retrieval query with the prior user turn; otherwise it returns the question
    # unchanged, so a first turn or a self-contained question retrieves exactly as
    # before (no regression to how documents/knowledge are found).
    from prompt_utils import build_followup_query
    retrieval_query = build_followup_query(question, history) if history else question

    citations = await rag_service.search_async(retrieval_query, top_k=top_k, project_id=project_id,
                                               artifact_id=artifact_id)
    knowledge: list[dict] = []
    if include_knowledge and artifact_id is None:
        knowledge = await rag_service.search_knowledge_async(retrieval_query, top_k=3)

    merged = citations + knowledge
    if not merged:
        return {"answer": "No indexed content found. Upload files, or install Knowledge "
                          "Packs from the + menu → Import Knowledge Pack, then ask again.",
                "citations": [], "model": model}
    # Structured /api/chat: retrieved evidence in the system message, prior
    # turns as real roles, the ORIGINAL question as the final user turn (so the
    # model answers the literal follow-up). No flattening — see
    # oyster/docs/AI_HANDOFF.md 2026-09-30. Citations are returned unchanged.
    messages = rag_service.build_rag_messages(question, merged, history=history)
    resolved = config.resolve_model(model)
    answer, quality_flags = await _generate_validated(
        lambda temperature: ollama_service.chat(
            messages, resolved, options={"temperature": temperature} if temperature is not None else None),
        citations=merged)
    return {"answer": answer, "citations": merged, "model": model, "quality_flags": quality_flags}


# Temperature for the corrective retry. The chat models run at temperature 0
# (deterministic), so a plain re-request reproduces the identical failing output
# — not a repair. The retry raises temperature so the second attempt genuinely
# differs; this is a bounded, corrective retry, not retry-until-compliant.
_RETRY_TEMPERATURE = 0.4


async def _generate_validated(make_call, citations: list | None = None) -> tuple[str, list[str]]:
    """Run a generation, validate it (Phase 6), and on a HARD failure make ONE
    corrective retry at a higher temperature before falling back to an honest
    uncertainty message. ``make_call(temperature)`` returns the generation
    coroutine; ``temperature=None`` means "use the model's own default" (first
    attempt), a float overrides it (retry). Returns (answer, flag_codes). Soft
    flags never replace a valid answer — only genuine hard failures do, and only
    after the retry also fails."""
    from services import output_validator as ov
    n_cites = len(citations or [])

    cite_texts = [(c.get("chunk") or c.get("content") or c.get("passage") or "")
                  for c in (citations or [])]

    def _finish(ans: str, res) -> tuple[str, list[str]]:
        flags = res.flag_codes()
        if not n_cites:
            return ans, flags
        # Strip markers that point past the real sources (claim support that
        # does not exist), then — only if the model cited nothing — attach
        # evidence-grounded markers so grounded claims are traceable. Both are
        # safe: neither invents a number without a matching source.
        ans = ov.repair_citation_markers(ans, n_cites)
        if not ov.valid_citation_markers(ans, n_cites):
            ans = ov.attribute_citations(ans, cite_texts)
            if ov.valid_citation_markers(ans, n_cites) and "missing_citation" in flags:
                flags = [f for f in flags if f != "missing_citation"] + ["citation_attributed"]
        return ans, flags

    answer = await make_call(None)
    result = ov.validate(answer, citations=citations, check_citation_markers=bool(citations))
    if result.ok:
        return _finish(answer, result)
    # One corrective, non-deterministic retry (different temperature) before giving up.
    answer2 = await make_call(_RETRY_TEMPERATURE)
    result2 = ov.validate(answer2, citations=citations, check_citation_markers=bool(citations))
    if result2.ok:
        return _finish(answer2, result2)
    log_config.audit("output_validation_failed",
                     {"first": result.flag_codes(), "second": result2.flag_codes()})
    return ov.UNCERTAINTY_MESSAGE, result2.flag_codes()


# ---------------------------------------------------------------------------
# Delete
# ---------------------------------------------------------------------------

async def delete(project_id: str, artifact_id: str) -> bool:
    rec = store.get(artifact_id)
    if not rec or rec["project_id"] != project_id:
        return False
    await rag_service.delete_artifact_async(artifact_id)
    # remove the original file(s)
    folder = config.ARTIFACTS_DIR / project_id
    if folder.exists():
        for p in folder.glob(f"{artifact_id}_*"):
            try:
                p.unlink()
            except OSError:
                pass
    # remove media thumbnail + sampled frames
    thumb = _thumb_path(project_id, artifact_id)
    if thumb.exists():
        try:
            thumb.unlink()
        except OSError:
            pass
    frames = _frames_dir(project_id, artifact_id)
    if frames.exists():
        import shutil
        shutil.rmtree(frames, ignore_errors=True)
    return store.delete(artifact_id)
