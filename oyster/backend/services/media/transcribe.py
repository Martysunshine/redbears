"""Local speech-to-text via faster-whisper (CTranslate2 — no torch, no cloud).

The model is loaded lazily on first use and cached. If faster-whisper is not
installed, callers get a clear dependency error (video with no speech still
succeeds — transcription is skipped, visual analysis continues).

Install:  pip install faster-whisper
Model size via OYSTER_WHISPER_MODEL (tiny|base|small|medium). Default "base".
"""

from __future__ import annotations

from pathlib import Path
from threading import Lock

import config

_model = None
_lock = Lock()
_import_error: str | None = None


def whisper_available() -> bool:
    try:
        import faster_whisper  # noqa: F401
        return True
    except Exception as exc:  # pragma: no cover
        global _import_error
        _import_error = str(exc)
        return False


def _get_model():
    global _model
    if _model is None:
        with _lock:
            if _model is None:
                from faster_whisper import WhisperModel

                _model = WhisperModel(
                    config.WHISPER_MODEL,
                    device="cpu",
                    compute_type=config.WHISPER_COMPUTE_TYPE,
                )
    return _model


def transcribe(audio_path: str | Path) -> dict:
    """Transcribe an audio file locally.

    Returns ``{"text": str, "segments": [{"start","end","text"}], "language": str}``.
    Raises ``RuntimeError`` if faster-whisper is unavailable.
    """
    if not whisper_available():
        raise RuntimeError(
            "faster-whisper not installed. Run: pip install faster-whisper"
            + (f" ({_import_error})" if _import_error else "")
        )
    model = _get_model()
    segments_iter, info = model.transcribe(
        str(audio_path), vad_filter=True, beam_size=1,
    )
    segments: list[dict] = []
    parts: list[str] = []
    for seg in segments_iter:
        text = (seg.text or "").strip()
        if not text:
            continue
        segments.append({
            "start": round(float(seg.start), 2),
            "end": round(float(seg.end), 2),
            "text": text,
        })
        parts.append(text)
    return {
        "text": " ".join(parts).strip(),
        "segments": segments,
        "language": getattr(info, "language", None),
    }
