"""Local video processing via ffmpeg / ffprobe.

All invocations use fixed argument arrays with ``shell=False`` — no user-supplied
ffmpeg arguments are ever interpolated, and every subprocess has a timeout.
Temporary artefacts are written to caller-provided directories that are cleaned
up by the caller. Nothing leaves the machine.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import config

FFMPEG = shutil.which("ffmpeg")
FFPROBE = shutil.which("ffprobe")


def ffmpeg_available() -> bool:
    return bool(FFMPEG and FFPROBE)


def _run(args: list[str], timeout: int) -> subprocess.CompletedProcess:
    return subprocess.run(
        args, capture_output=True, timeout=timeout, shell=False, check=False,
    )


def probe(path: str | Path) -> dict:
    """Return validated media metadata via ffprobe. Raises on non-media input."""
    if not FFPROBE:
        raise RuntimeError("ffprobe not installed. Install with: brew install ffmpeg")
    args = [
        FFPROBE, "-v", "error", "-print_format", "json",
        "-show_format", "-show_streams", str(path),
    ]
    proc = _run(args, timeout=60)
    if proc.returncode != 0:
        raise RuntimeError("Not a valid/parseable media file (ffprobe failed).")
    try:
        info = json.loads(proc.stdout or b"{}")
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"ffprobe returned invalid JSON: {exc}") from exc

    fmt = info.get("format", {})
    streams = info.get("streams", [])
    video = next((s for s in streams if s.get("codec_type") == "video"), None)
    audios = [s for s in streams if s.get("codec_type") == "audio"]
    if video is None:
        raise RuntimeError("File has no video stream.")

    def _fps(v: dict) -> float:
        rate = v.get("avg_frame_rate") or v.get("r_frame_rate") or "0/1"
        try:
            num, den = rate.split("/")
            den_f = float(den)
            return round(float(num) / den_f, 2) if den_f else 0.0
        except (ValueError, ZeroDivisionError):
            return 0.0

    duration = float(fmt.get("duration") or video.get("duration") or 0.0)
    return {
        "duration_seconds": round(duration, 2),
        "video_codec": video.get("codec_name"),
        "width": video.get("width"),
        "height": video.get("height"),
        "resolution": f"{video.get('width')}x{video.get('height')}",
        "fps": _fps(video),
        "has_audio": bool(audios),
        "audio_codec": audios[0].get("codec_name") if audios else None,
        "audio_tracks": len(audios),
        "size_bytes": int(fmt.get("size") or 0),
        "format_name": fmt.get("format_name"),
    }


def thumbnail(path: str | Path, out_path: str | Path, at_seconds: float = 1.0,
              max_dim: int | None = None) -> bool:
    """Grab a single representative frame as a JPEG thumbnail."""
    if not FFMPEG:
        return False
    dim = max_dim or config.IMAGE_THUMBNAIL_SIZE
    args = [
        FFMPEG, "-y", "-ss", str(max(0.0, at_seconds)), "-i", str(path),
        "-frames:v", "1",
        "-vf", f"scale='min({dim},iw)':-2",
        "-q:v", "3", str(out_path),
    ]
    proc = _run(args, timeout=60)
    return proc.returncode == 0 and Path(out_path).exists()


def extract_audio(path: str | Path, out_wav: str | Path) -> bool:
    """Extract mono 16 kHz WAV for transcription. Returns False if no audio."""
    if not FFMPEG:
        return False
    args = [
        FFMPEG, "-y", "-i", str(path), "-vn",
        "-ac", "1", "-ar", "16000", "-f", "wav", str(out_wav),
    ]
    proc = _run(args, timeout=config.VIDEO_PROCESSING_TIMEOUT_SECONDS)
    return proc.returncode == 0 and Path(out_wav).exists() and Path(out_wav).stat().st_size > 44


def sample_frames(path: str | Path, out_dir: str | Path, duration: float) -> list[tuple[int, str]]:
    """Sample frames at a fixed interval, capped at VIDEO_MAX_FRAMES.

    Returns a list of ``(timestamp_seconds, frame_path)``.
    """
    if not FFMPEG or duration <= 0:
        return []
    out_dir = Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    interval = max(1, config.VIDEO_FRAME_INTERVAL_SECONDS)
    max_frames = max(1, config.VIDEO_MAX_FRAMES)

    # Evenly spaced timestamps, but never exceed max_frames.
    n = min(max_frames, max(1, int(duration // interval) + 1))
    if n == 1:
        stamps = [max(0.0, min(duration / 2, duration - 0.1))]
    else:
        step = duration / n
        stamps = [round(step * (i + 0.5), 2) for i in range(n)]

    frames: list[tuple[int, str]] = []
    for ts in stamps:
        fp = out_dir / f"frame_{int(ts):05d}.jpg"
        args = [
            FFMPEG, "-y", "-ss", str(ts), "-i", str(path), "-frames:v", "1",
            "-vf", "scale='min(1024,iw)':-2", "-q:v", "4", str(fp),
        ]
        proc = _run(args, timeout=60)
        if proc.returncode == 0 and fp.exists():
            frames.append((int(ts), str(fp)))
    return frames
