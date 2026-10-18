"""Project-scoped artifact ingestion API.

Files, folders and notes → extracted, chunked, embedded (project/artifact-scoped
RAG). The legacy /documents/* endpoints are preserved elsewhere for compatibility.

**Attachments are public** — anyone, including anonymous visitors, may upload
and query their own. That is a deliberate product decision and it is preserved
here. What is NOT preserved is trusting the URL: every route below receives an
``ArtifactScope`` from ``services/artifact_scope.py`` and uses
``scope.project_id``, which is derived from the CALLER'S IDENTITY, never from
the ``{project_id}`` in the path. Non-admins get a sandbox of their own; only
operators can address a project by name.

Do not add a route here that reads ``project_id`` directly — the path
parameter is declared by the dependency precisely so routes cannot see it.
"""

from __future__ import annotations

import asyncio
import re
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse

import config
import log_config
from models.schemas import ArtifactAskRequest, ArtifactSummarizeRequest, NoteCreateRequest
from services import project_service
from services.artifact_scope import ArtifactScope, artifact_scope
from services.artifacts import service as artifact_service
from services.artifacts import store as artifact_store

router = APIRouter(tags=["artifacts"])

_FRAME_NAME = re.compile(r"^frame_\d{1,7}\.jpg$")


async def _read_bounded(upload: UploadFile, limit: int) -> bytes:
    """Read an upload only after checking its spooled size.

    ``UploadFile`` is already backed by a spooled temporary file, but calling
    ``read()`` first still creates an unbounded second copy in Python memory.
    Seek-based sizing keeps oversized requests from becoming a RAM pressure
    incident before the authoritative per-file and quota checks run.
    """
    file = upload.file
    await asyncio.to_thread(file.seek, 0, 2)
    size = file.tell()
    if size > limit:
        raise HTTPException(status_code=413, detail=f"File exceeds configured size ({limit // (1024 * 1024)} MB maximum).")
    await asyncio.to_thread(file.seek, 0)
    return await upload.read()


def _require_project(project_id: str) -> None:
    if project_service.get_project(project_id) is None:
        raise HTTPException(status_code=404, detail=f"Project '{project_id}' not found.")


def _owned(project_id: str, artifact_id: str) -> dict:
    rec = artifact_store.get(artifact_id)
    if not rec or rec["project_id"] != project_id:
        # 404, never 403: a distinguishable "exists but not yours" turns this
        # into an id oracle.
        raise HTTPException(status_code=404, detail="Artifact not found.")
    return rec


@router.post("/projects/{project_id}/artifacts/upload")
async def upload_artifacts(files: list[UploadFile] = File(...),
                           conversation_id: str | None = Form(None),
                           scope: ArtifactScope = Depends(artifact_scope)):
    _require_project(scope.project_id)
    scope.charge_upload(len(files))
    results = []
    for f in files:
        content = await _read_bounded(f, config.MAX_UPLOAD_BYTES)
        # Per-file, so a batch stops at the point it would exceed the cap
        # rather than being rejected wholesale after the last byte is read.
        scope.assert_can_store(len(content))
        rec = await artifact_service.ingest_file(
            scope.project_id, f.filename or "unnamed", content, conversation_id=conversation_id
        )
        results.append(rec)
    log_config.audit("artifacts_upload", {"project_id": scope.project_id,
                                          "tier": scope.tier, "count": len(results)})
    return {"artifacts": results, "total": len(results)}


@router.post("/projects/{project_id}/artifacts/upload-folder")
async def upload_folder(files: list[UploadFile] = File(...),
                        paths: list[str] = Form(...),
                        conversation_id: str | None = Form(None),
                        scope: ArtifactScope = Depends(artifact_scope)):
    _require_project(scope.project_id)
    if len(files) > config.MAX_FOLDER_FILES:
        raise HTTPException(status_code=413,
                            detail=f"Too many files ({len(files)} > {config.MAX_FOLDER_FILES}).")
    scope.charge_upload(len(files))
    collected: list[tuple[str, bytes]] = []
    total = 0
    for f, rel in zip(files, paths):
        content = await _read_bounded(f, config.MAX_UPLOAD_BYTES)
        total += len(content)
        if total > config.MAX_FOLDER_BYTES:
            raise HTTPException(status_code=413, detail="Folder exceeds total size limit.")
        scope.assert_can_store(len(content))
        collected.append((rel or (f.filename or "unnamed"), content))
    result = await artifact_service.ingest_folder(scope.project_id, collected,
                                                  conversation_id=conversation_id)
    log_config.audit("folder_upload", {"project_id": scope.project_id, "tier": scope.tier,
                                       "ingested": result["ingested"],
                                       "skipped": len(result["skipped"])})
    return result


@router.post("/projects/{project_id}/artifacts/images")
async def upload_images(files: list[UploadFile] = File(...),
                        conversation_id: str | None = Form(None),
                        scope: ArtifactScope = Depends(artifact_scope)):
    _require_project(scope.project_id)
    scope.charge_upload(len(files))
    results = []
    for f in files:
        content = await _read_bounded(f, config.MAX_IMAGE_SIZE_MB * 1024 * 1024)
        scope.assert_can_store(len(content))
        try:
            rec = await artifact_service.ingest_media(
                scope.project_id, f.filename or "image", content, conversation_id=conversation_id)
        except ValueError as exc:
            log_config.error("images_upload", str(exc), {"filename": f.filename})
            raise HTTPException(
                status_code=415,
                detail=f"Unsupported image type. Accepted: {', '.join(sorted(config.IMAGE_EXTENSIONS))}",
            ) from exc
        results.append(rec)
    log_config.audit("images_upload", {"project_id": scope.project_id,
                                       "tier": scope.tier, "count": len(results)})
    return {"artifacts": results, "total": len(results)}


@router.post("/projects/{project_id}/artifacts/videos")
async def upload_videos(files: list[UploadFile] = File(...),
                        conversation_id: str | None = Form(None),
                        scope: ArtifactScope = Depends(artifact_scope)):
    _require_project(scope.project_id)
    # Video is the most expensive path on this box (ffmpeg + Whisper + per-frame
    # vision on 2 cores), so it costs the caller more of their allowance than a
    # plain file does.
    scope.charge_upload(len(files) * 3)
    results = []
    for f in files:
        content = await _read_bounded(f, config.MAX_VIDEO_SIZE_MB * 1024 * 1024)
        scope.assert_can_store(len(content))
        try:
            rec = await artifact_service.ingest_media(
                scope.project_id, f.filename or "video", content, conversation_id=conversation_id)
        except ValueError as exc:
            log_config.error("videos_upload", str(exc), {"filename": f.filename})
            raise HTTPException(
                status_code=415,
                detail=f"Unsupported video type. Accepted: {', '.join(sorted(config.VIDEO_EXTENSIONS))}",
            ) from exc
        results.append(rec)
    log_config.audit("videos_upload", {"project_id": scope.project_id,
                                       "tier": scope.tier, "count": len(results)})
    return {"artifacts": results, "total": len(results)}


@router.get("/projects/{project_id}/artifacts/{artifact_id}/file")
async def get_artifact_file(artifact_id: str, scope: ArtifactScope = Depends(artifact_scope)):
    """Controlled download/preview of the original media (no raw FS paths)."""
    _owned(scope.project_id, artifact_id)
    # Paths are not in the public projection — fetched only after ownership.
    rec = artifact_store.get(artifact_id, with_paths=True) or {}
    path = rec.get("storage_path")
    if not path or not Path(path).exists():
        raise HTTPException(status_code=404, detail="File not available.")
    return FileResponse(path, media_type=rec.get("mime") or "application/octet-stream",
                        filename=rec.get("original_filename") or rec["filename"])


@router.get("/projects/{project_id}/artifacts/{artifact_id}/thumbnail")
async def get_artifact_thumbnail(artifact_id: str, scope: ArtifactScope = Depends(artifact_scope)):
    _owned(scope.project_id, artifact_id)
    rec = artifact_store.get(artifact_id, with_paths=True) or {}
    thumb = rec.get("thumbnail_path")
    if not thumb or not Path(thumb).exists():
        raise HTTPException(status_code=404, detail="No thumbnail.")
    return FileResponse(thumb, media_type="image/jpeg")


@router.get("/projects/{project_id}/artifacts/{artifact_id}/frame/{name}")
async def get_artifact_frame(artifact_id: str, name: str,
                             scope: ArtifactScope = Depends(artifact_scope)):
    _owned(scope.project_id, artifact_id)
    if not _FRAME_NAME.match(name):  # reject traversal / arbitrary names
        raise HTTPException(status_code=400, detail="Invalid frame name.")
    frame = config.ARTIFACTS_DIR / scope.project_id / "frames" / artifact_id / name
    if not frame.exists():
        raise HTTPException(status_code=404, detail="Frame not found.")
    return FileResponse(str(frame), media_type="image/jpeg")


@router.post("/projects/{project_id}/artifacts/{artifact_id}/reprocess")
async def reprocess_artifact(artifact_id: str, scope: ArtifactScope = Depends(artifact_scope)):
    # Ownership first: reprocess re-runs the expensive media pipeline, so it
    # must not be triggerable against someone else's artifact.
    _owned(scope.project_id, artifact_id)
    scope.charge_upload(1)
    rec = await artifact_service.reprocess(scope.project_id, artifact_id)
    if rec is None:
        raise HTTPException(status_code=404, detail="Cannot reprocess this artifact.")
    return {"artifact": rec}


@router.post("/projects/{project_id}/artifacts/note")
async def create_note(request: NoteCreateRequest,
                      scope: ArtifactScope = Depends(artifact_scope)):
    _require_project(scope.project_id)
    scope.charge_upload(1)
    scope.assert_can_store(len((request.content or "").encode("utf-8")))
    rec = await artifact_service.ingest_note(scope.project_id, request.title, request.content,
                                             conversation_id=request.conversation_id)
    return {"artifact": rec}


@router.get("/projects/{project_id}/artifacts")
async def list_artifacts(scope: ArtifactScope = Depends(artifact_scope)):
    _require_project(scope.project_id)
    items = artifact_store.list_for_project(scope.project_id)
    return {"artifacts": items, "total": len(items)}


@router.get("/projects/{project_id}/artifacts/{artifact_id}")
async def get_artifact(artifact_id: str, scope: ArtifactScope = Depends(artifact_scope)):
    return {"artifact": _owned(scope.project_id, artifact_id)}


@router.get("/projects/{project_id}/artifacts/{artifact_id}/status")
async def artifact_status(artifact_id: str, scope: ArtifactScope = Depends(artifact_scope)):
    rec = _owned(scope.project_id, artifact_id)
    return {"id": artifact_id, "status": rec["status"], "extract_status": rec["extract_status"],
            "index_status": rec["index_status"], "chunk_count": rec["chunk_count"], "error": rec["error"]}


@router.delete("/projects/{project_id}/artifacts/{artifact_id}")
async def delete_artifact(artifact_id: str, scope: ArtifactScope = Depends(artifact_scope)):
    _owned(scope.project_id, artifact_id)
    ok = await artifact_service.delete(scope.project_id, artifact_id)
    if not ok:
        raise HTTPException(status_code=404, detail="Artifact not found.")
    log_config.audit("artifact_deleted", {"project_id": scope.project_id,
                                          "tier": scope.tier, "artifact_id": artifact_id})
    return {"status": "ok", "deleted": artifact_id}


@router.post("/projects/{project_id}/artifacts/{artifact_id}/summarize")
async def summarize_artifact(artifact_id: str, request: ArtifactSummarizeRequest,
                             scope: ArtifactScope = Depends(artifact_scope)):
    _owned(scope.project_id, artifact_id)
    result = await artifact_service.summarize(scope.project_id, artifact_id, request.model)
    if result is None:
        raise HTTPException(status_code=404, detail="Artifact not found.")
    return result


@router.post("/projects/{project_id}/artifacts/{artifact_id}/ask")
async def ask_artifact(artifact_id: str, request: ArtifactAskRequest,
                       scope: ArtifactScope = Depends(artifact_scope)):
    _owned(scope.project_id, artifact_id)
    return await artifact_service.ask(scope.project_id, request.question, artifact_id=artifact_id,
                                      model=request.model, top_k=request.top_k,
                                      history=request.history)


@router.post("/projects/{project_id}/artifacts/ask")
async def ask_project(request: ArtifactAskRequest,
                      scope: ArtifactScope = Depends(artifact_scope)):
    _require_project(scope.project_id)
    return await artifact_service.ask(scope.project_id, request.question, model=request.model,
                                      top_k=request.top_k, history=request.history)
