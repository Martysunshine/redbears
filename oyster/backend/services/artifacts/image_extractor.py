"""Image artifact processing — fully local.

Pipeline:  validate (content-based) → Pillow metadata + safe EXIF (GPS stripped)
→ thumbnail → optional Tesseract OCR → Ollama vision-language analysis →
assemble indexable segments + metadata.

SVG is handled without rendering: parsed with defusedxml (no script execution,
no external entity/URL fetching) to pull out text and dimensions only.
"""

from __future__ import annotations

import asyncio
from pathlib import Path

import config
from services.media import ocr, redact, vision

# Guard against decompression bombs.
_MAX_PIXELS = 64_000_000  # ~64 MP

# EXIF tags that are safe/useful to surface (GPS is deliberately excluded).
_SAFE_EXIF = {
    "Make", "Model", "Software", "DateTime", "DateTimeOriginal", "Orientation",
    "ExifImageWidth", "ExifImageHeight", "LensModel", "FNumber", "ISOSpeedRatings",
    "FocalLength", "ExposureTime",
}


class ImageError(Exception):
    """Raised when an image cannot be processed."""


def _is_svg(path: Path, filename: str) -> bool:
    if Path(filename).suffix.lower() == ".svg":
        return True
    try:
        head = path.read_bytes()[:512].lstrip()
        return head[:5].lower() == b"<?xml" and b"<svg" in path.read_bytes()[:2048].lower() \
            or head[:4].lower() == b"<svg"
    except OSError:
        return False


def _pillow_meta(path: Path) -> dict:
    """Open with Pillow, verify it is a real image, pull metadata + safe EXIF."""
    from PIL import Image, ExifTags
    Image.MAX_IMAGE_PIXELS = _MAX_PIXELS
    try:
        with Image.open(path) as im:
            im.verify()  # detects truncated/corrupt files
    except Exception as exc:
        # ImageError text reaches the uploader verbatim (stored on the record);
        # Pillow's own words stay on the exception chain, for the log only.
        raise ImageError("Malformed or unreadable image.") from exc

    try:
        with Image.open(path) as im:
            width, height = im.size
            fmt, mode = im.format, im.mode
            exif_out: dict = {}
            try:
                raw_exif = im.getexif()
                for tag_id, value in raw_exif.items():
                    name = ExifTags.TAGS.get(tag_id, str(tag_id))
                    if name in _SAFE_EXIF:
                        if isinstance(value, bytes):
                            continue
                        exif_out[name] = str(value)[:120]
            except Exception:
                pass
    except Exception as exc:
        raise ImageError("Could not decode this image.") from exc

    return {"width": width, "height": height, "format": fmt, "mode": mode, "exif": exif_out}


def _make_thumbnail(path: Path, out_path: Path) -> bool:
    from PIL import Image
    try:
        with Image.open(path) as im:
            im = im.convert("RGB") if im.mode not in ("RGB", "L") else im
            im.thumbnail((config.IMAGE_THUMBNAIL_SIZE, config.IMAGE_THUMBNAIL_SIZE))
            im.save(out_path, "JPEG", quality=82)
        return out_path.exists()
    except Exception:
        return False


def make_thumbnail(path: str | Path, out_path: str | Path) -> bool:
    """Create the preview independently of the slower OCR/VLM pipeline."""
    return _make_thumbnail(Path(path), Path(out_path))


# Max dimension of the copy handed to the vision model — keeps OCR of small text
# legible while staying well within Ollama's image limits.
_VLM_MAX_DIM = 1600


def _normalize_for_vlm(path: Path, out_path: Path) -> bool:
    """Re-encode to a plain RGB PNG the local VLM reliably accepts.

    Ollama rejects some containers/modes (e.g. WebP, palette, CMYK) with a 400.
    Normalizing to PNG makes every supported raster format work.
    """
    from PIL import Image
    try:
        with Image.open(path) as im:
            if getattr(im, "is_animated", False):
                im.seek(0)
            im = im.convert("RGB")
            if max(im.size) > _VLM_MAX_DIM:
                im.thumbnail((_VLM_MAX_DIM, _VLM_MAX_DIM))
            im.save(out_path, "PNG")
        return out_path.exists()
    except Exception:
        return False


def _svg_extract(path: Path) -> dict:
    """Safely parse an SVG for text + dimensions (no rendering, no fetching)."""
    import defusedxml.ElementTree as ET
    try:
        tree = ET.parse(str(path), forbid_dtd=True, forbid_entities=True, forbid_external=True)
    except Exception as exc:
        raise ImageError("Unsafe or invalid SVG.") from exc
    root = tree.getroot()
    texts = [t.strip() for t in (e.text or "" for e in root.iter()) if t and t.strip()]
    width = root.get("width")
    height = root.get("height")
    return {"width": width, "height": height, "format": "SVG", "mode": "vector",
            "exif": {}, "svg_text": texts}


async def process(path: str, filename: str, thumbnail_out: str,
                  project_id: str | None = None) -> dict:
    """Process one image. Returns {segments, metadata, text, analysis_status}."""
    p = Path(path)

    # --- SVG path: text-only, no raster, no VLM ---------------------------
    if _is_svg(p, filename):
        meta = await asyncio.to_thread(_svg_extract, p)
        svg_text = meta.pop("svg_text", [])
        text_blob = "\n".join(svg_text)
        segments = []
        if text_blob.strip():
            segments.append({"content_type": "ocr", "text": f"[SVG text] {text_blob}"})
        analysis = {
            "description": "Vector SVG image (parsed safely; not rasterized). "
                           "Text content extracted from the markup.",
            "visible_text": svg_text, "objects": [], "security_observations": [],
            "possible_secrets": redact.scan(text_blob), "error_messages": [],
        }
        segments.append({"content_type": "caption", "text": analysis["description"]})
        return {
            "segments": segments,
            "text": _combine_text(filename, analysis, ""),
            "metadata": {**meta, **analysis, "ocr_text": text_blob, "model": None,
                         "thumbnail": False},
            "analysis_status": "skipped",  # no VLM for vector images
        }

    # --- Raster images ----------------------------------------------------
    meta = await asyncio.to_thread(_pillow_meta, p)
    await asyncio.to_thread(_make_thumbnail, p, Path(thumbnail_out))

    ocr_text = await asyncio.to_thread(ocr.ocr_image, p)

    # Hand the VLM a normalized PNG (WebP/GIF/CMYK/palette → RGB PNG).
    import tempfile
    vlm_src = str(p)
    _tmp = Path(tempfile.gettempdir()) / f"oyster_vlm_{p.stem}.png"
    if await asyncio.to_thread(_normalize_for_vlm, p, _tmp):
        vlm_src = str(_tmp)

    analysis_status = "ok"
    try:
        analysis = await vision.analyze_image(vlm_src, project_id=project_id)
    except vision.VisionUnavailable as exc:
        # No VLM installed — still keep OCR + metadata (do not fail the artifact
        # if we at least got OCR text); mark analysis skipped with the reason.
        analysis = {"description": "", "visible_text": [], "objects": [],
                    "security_observations": [], "possible_secrets": [],
                    "error_messages": [], "_error": str(exc)}
        analysis_status = "skipped"
    finally:
        if _tmp.exists():
            try:
                _tmp.unlink()
            except OSError:
                pass

    # OCR augments the VLM's visible_text (dedupe, keep both sources).
    if ocr_text:
        combined = list(dict.fromkeys([*analysis.get("visible_text", []), ocr_text]))
        analysis["visible_text"] = combined

    # --- Secret handling: scan RAW text for indicators, then REDACT every text
    #     field so nothing downstream (preview, RAG index, logs) exposes a full
    #     secret value. The operator can still open the original image to read it.
    all_text = "\n".join([*analysis.get("visible_text", []), ocr_text])
    scanned = redact.scan(all_text) if all_text.strip() else []
    model_secrets = [redact.redact(s) for s in (analysis.get("possible_secrets") or [])]
    possible_secrets = list(dict.fromkeys(
        [*model_secrets, *[f"{s['type']}: {s['masked']}" for s in scanned]]
    ))

    ocr_text = redact.redact(ocr_text)
    analysis["visible_text"] = [redact.redact(t) for t in analysis.get("visible_text", [])]
    analysis["description"] = redact.redact(analysis.get("description", ""))
    analysis["security_observations"] = [redact.redact(t) for t in analysis.get("security_observations", [])]
    analysis["error_messages"] = [redact.redact(t) for t in analysis.get("error_messages", [])]
    analysis["possible_secrets"] = possible_secrets

    segments = _build_segments(analysis, ocr_text)
    return {
        "segments": segments,
        "text": _combine_text(filename, analysis, ocr_text),
        "metadata": {
            "width": meta["width"], "height": meta["height"], "format": meta["format"],
            "mode": meta["mode"], "exif": meta["exif"], "ocr_text": ocr_text,
            "ocr_engine": "tesseract" if ocr.tesseract_available() else "vlm",
            "description": analysis.get("description", ""),
            "objects": analysis.get("objects", []),
            "security_observations": analysis.get("security_observations", []),
            "possible_secrets": possible_secrets,
            "error_messages": analysis.get("error_messages", []),
            "model": analysis.get("model"),
            "thumbnail": True,
        },
        "analysis_status": analysis_status,
    }


def _build_segments(analysis: dict, ocr_text: str) -> list[dict]:
    segs: list[dict] = []
    desc = analysis.get("description", "")
    if desc:
        segs.append({"content_type": "caption", "text": desc})
    vis = analysis.get("visible_text") or []
    if vis:
        segs.append({"content_type": "ocr", "text": "Visible text:\n" + "\n".join(vis)})
    sec = analysis.get("security_observations") or []
    if sec:
        segs.append({"content_type": "caption", "text": "Security observations:\n" + "\n".join(sec)})
    if ocr_text and ocr_text not in "\n".join(vis):
        segs.append({"content_type": "ocr", "text": ocr_text})
    return segs or [{"content_type": "caption", "text": "Image with no extractable text."}]


def _combine_text(filename: str, analysis: dict, ocr_text: str) -> str:
    parts = [f"IMAGE: {filename}"]
    if analysis.get("description"):
        parts.append("Description: " + analysis["description"])
    if analysis.get("visible_text"):
        parts.append("Visible text:\n" + "\n".join(analysis["visible_text"]))
    if analysis.get("objects"):
        parts.append("Objects: " + ", ".join(analysis["objects"]))
    if analysis.get("security_observations"):
        parts.append("Security observations:\n" + "\n".join(analysis["security_observations"]))
    if analysis.get("error_messages"):
        parts.append("Errors:\n" + "\n".join(analysis["error_messages"]))
    if ocr_text and ocr_text not in "\n".join(analysis.get("visible_text", [])):
        parts.append("OCR:\n" + ocr_text)
    return "\n\n".join(parts)
