"""Video artifact processing — fully local.

Pipeline:  ffprobe validate/metadata → poster thumbnail → extract audio →
faster-whisper transcription (with timestamps) → sample frames → vision-language
analysis per frame → assemble a timeline + indexable segments.

Streaming/subprocess-safe: the whole video is never loaded into memory; frames
and audio go through ffmpeg into a temp dir which is cleaned up here.
"""

from __future__ import annotations

import asyncio
import tempfile
from pathlib import Path

import config
import log_config
from services.media import redact, transcribe, video_probe, vision


class VideoError(Exception):
    """Raised when a video cannot be processed (with an actionable message)."""


def _fmt_ts(seconds: float) -> str:
    seconds = int(seconds)
    m, s = divmod(seconds, 60)
    h, m = divmod(m, 60)
    return f"{h:02d}:{m:02d}:{s:02d}" if h else f"{m:02d}:{s:02d}"


async def process(path: str, filename: str, thumbnail_out: str, frames_dir: str,
                  project_id: str | None = None,
                  on_status=None) -> dict:
    """Process one video. ``on_status(state)`` is an optional progress callback."""
    if not video_probe.ffmpeg_available():
        # VideoError text reaches the uploader verbatim (stored on the record):
        # no operator instructions, no tool names, no probe output.
        log_config.error("video_process", "ffmpeg/ffprobe not installed", {"filename": filename})
        raise VideoError("Video processing is not available on this server right now.")

    async def _status(state: str) -> None:
        if on_status:
            await on_status(state)

    # --- validate + metadata (ffprobe) -----------------------------------
    await _status("validating")
    try:
        meta = await asyncio.to_thread(video_probe.probe, path)
    except RuntimeError as exc:
        log_config.error("video_probe", str(exc), {"filename": filename})
        raise VideoError("Could not read this video file.") from exc

    duration = meta["duration_seconds"]
    if duration > config.MAX_VIDEO_DURATION_SECONDS:
        raise VideoError(
            f"Video too long ({int(duration)}s > {config.MAX_VIDEO_DURATION_SECONDS}s limit)."
        )

    frames_path = Path(frames_dir)
    frames_path.mkdir(parents=True, exist_ok=True)

    # poster thumbnail (best-effort)
    await asyncio.to_thread(video_probe.thumbnail, path, thumbnail_out,
                            min(1.0, duration / 2), None)

    segments: list[dict] = []
    warnings: list[str] = []

    # --- transcription ----------------------------------------------------
    transcript = {"text": "", "segments": [], "language": None}
    with tempfile.TemporaryDirectory() as td:
        if meta["has_audio"]:
            await _status("transcribing")
            wav = Path(td) / "audio.wav"
            has_audio = await asyncio.to_thread(video_probe.extract_audio, path, wav)
            if has_audio and transcribe.whisper_available():
                try:
                    transcript = await asyncio.to_thread(transcribe.transcribe, wav)
                except Exception as exc:  # transcription failure shouldn't kill the artifact
                    # warnings land in the artifact's metadata, which the
                    # uploader can read — keep the cause in the log.
                    log_config.error("video_transcribe", str(exc), {"filename": filename})
                    warnings.append("Transcription failed.")
            elif has_audio:
                warnings.append("Audio was not transcribed: speech-to-text is not "
                                "available on this server.")
        else:
            warnings.append("No audio track — visual analysis only.")

    for seg in transcript["segments"]:
        ts = f"[{_fmt_ts(seg['start'])}–{_fmt_ts(seg['end'])}]"
        segments.append({
            "content_type": "transcript",
            "text": f"{ts} {seg['text']}",
            "timestamp_start": seg["start"],
            "timestamp_end": seg["end"],
        })

    # --- frame sampling + vision -----------------------------------------
    await _status("analyzing")
    sampled = await asyncio.to_thread(video_probe.sample_frames, path, frames_path, duration)
    frame_records: list[dict] = []
    vlm_ok = await vision.vision_available()
    if not vlm_ok and sampled:
        warnings.append("Frames were not described: no vision model is available on this server.")

    for ts, fpath in sampled:
        rec = {
            "timestamp_seconds": ts,
            "thumbnail_path": Path(fpath).name,
            "description": "",
            "visible_text": [],
            "security_observations": [],
        }
        if vlm_ok:
            try:
                fa = await vision.describe_frame(fpath, context=f"at {_fmt_ts(ts)}")
                rec["description"] = fa.get("description", "")
                rec["visible_text"] = fa.get("visible_text", [])
                rec["security_observations"] = fa.get("security_observations", [])
            except Exception as exc:  # noqa: BLE001
                log_config.error("video_frame", str(exc), {"filename": filename, "ts": ts})
                warnings.append(f"Frame {_fmt_ts(ts)} analysis failed.")
        frame_records.append(rec)

        stamp = f"[{_fmt_ts(ts)}]"
        body_bits = [rec["description"], *rec["visible_text"], *rec["security_observations"]]
        body = " ".join(b for b in body_bits if b).strip()
        if body:
            segments.append({
                "content_type": "frame_description",
                "text": f"{stamp} {body}",
                "timestamp_start": float(ts),
                "timestamp_end": float(ts),
                "frame_index": len(frame_records) - 1,
            })

    # --- aggregate security observations + secret indicators -------------
    security_observations = []
    for r in frame_records:
        security_observations.extend(r["security_observations"])
    all_readable = "\n".join(
        [transcript["text"], *(t for r in frame_records for t in r["visible_text"])]
    )
    possible_secrets = [f"{s['type']}: {s['masked']}" for s in redact.scan(all_readable)]

    # Redact any full secret values everywhere they'd be surfaced (transcript,
    # frame text, segments, previews, RAG index, logs). Original file remains.
    transcript["text"] = redact.redact(transcript["text"])
    for seg in transcript["segments"]:
        seg["text"] = redact.redact(seg["text"])
    for r in frame_records:
        r["visible_text"] = [redact.redact(t) for t in r["visible_text"]]
        r["description"] = redact.redact(r["description"])
        r["security_observations"] = [redact.redact(t) for t in r["security_observations"]]
    for seg in segments:
        seg["text"] = redact.redact(seg["text"])
    security_observations = [redact.redact(o) for o in security_observations]

    # --- summary (best-effort, local chat model) -------------------------
    await _status("indexing")
    summary = await _summarize(filename, meta, transcript, frame_records)

    # ensure there is always something indexable
    if not segments:
        segments.append({
            "content_type": "summary",
            "text": f"Video {filename}: {meta['resolution']}, {_fmt_ts(duration)} long. "
                    + (summary or "No transcript or frame text extracted."),
        })
    if summary:
        segments.insert(0, {"content_type": "summary", "text": summary})

    text_blob = _combine_text(filename, meta, transcript, frame_records, summary)
    metadata = {
        **meta,
        "transcript": transcript["text"],
        "transcript_segments": transcript["segments"],
        "language": transcript["language"],
        "frames": frame_records,
        "summary": summary,
        "security_observations": security_observations,
        "possible_secrets": possible_secrets,
        "warnings": warnings,
        "vision_model": config.VISION_MODEL if vlm_ok else None,
        "whisper_model": config.WHISPER_MODEL if transcript["segments"] else None,
        "thumbnail": Path(thumbnail_out).exists(),
    }
    analysis_status = "ok" if (frame_records or transcript["segments"]) else "skipped"
    log_config.audit("video_process", {"project_id": project_id, "video": filename,
                                        "frames": len(frame_records),
                                        "transcript_segments": len(transcript["segments"]),
                                        "warnings": len(warnings)})
    return {"segments": segments, "text": text_blob, "metadata": metadata,
            "analysis_status": analysis_status}


async def _summarize(filename: str, meta: dict, transcript: dict,
                     frames: list[dict]) -> str:
    from services import ollama_service
    context_parts = []
    if transcript["text"]:
        context_parts.append("TRANSCRIPT:\n" + transcript["text"][:6000])
    if frames:
        fd = "\n".join(f"[{_fmt_ts(f['timestamp_seconds'])}] {f['description']}"
                       for f in frames if f["description"])
        if fd:
            context_parts.append("KEYFRAMES:\n" + fd[:4000])
    if not context_parts:
        return ""
    prompt = (
        "You are analyzing a screen-recording/video for a security operator. "
        "Using the transcript and keyframe descriptions below, write a concise "
        "summary (4-6 sentences): what happens, notable commands/errors, and any "
        "security-relevant observations. Reference timestamps where useful.\n\n"
        f"VIDEO: {filename} ({meta['resolution']}, {_fmt_ts(meta['duration_seconds'])})\n\n"
        + "\n\n".join(context_parts) + "\n\nSummary:"
    )
    try:
        return (await ollama_service.generate(prompt, config.resolve_model("dolphin-llama3"))).strip()
    except Exception:
        return ""


def _combine_text(filename: str, meta: dict, transcript: dict,
                  frames: list[dict], summary: str) -> str:
    parts = [f"VIDEO: {filename}",
             f"Duration: {_fmt_ts(meta['duration_seconds'])}  Resolution: {meta['resolution']}  "
             f"Codec: {meta['video_codec']}  Audio: {'yes' if meta['has_audio'] else 'no'}"]
    if summary:
        parts.append("Summary:\n" + summary)
    if transcript["text"]:
        parts.append("Transcript:\n" + transcript["text"])
    fd = "\n".join(f"[{_fmt_ts(f['timestamp_seconds'])}] {f['description']} "
                   + (" | ".join(f["visible_text"]) if f["visible_text"] else "")
                   for f in frames if f["description"] or f["visible_text"])
    if fd:
        parts.append("Keyframes:\n" + fd)
    return "\n\n".join(parts)[: config.MAX_ARTIFACT_TEXT_CHARS]
