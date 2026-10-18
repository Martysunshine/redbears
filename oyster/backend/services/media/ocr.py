"""Optional local OCR.

Environment inspection found no PaddleOCR / EasyOCR / Tesseract installed, and
torch 2.12 is present but torchvision is not — so pulling EasyOCR/PaddleOCR
risks a torch/torchvision ABI conflict. We therefore treat OCR as OPTIONAL:

- If Tesseract (``pytesseract`` + the ``tesseract`` binary) is available it is
  used for a fast, dedicated text pass.
- Otherwise text is read by the vision-language model itself (``vision.py``
  returns ``visible_text``), which for qwen2.5-VL is high quality.

Set ``OYSTER_OCR_ENGINE=tesseract`` to require it, or ``none`` to disable.
Install Tesseract with:  brew install tesseract
"""

from __future__ import annotations

import shutil
from pathlib import Path

import config

_available: bool | None = None

# The backend can run under launchd with a minimal PATH (/usr/bin:/bin:/usr/sbin:
# /sbin) that excludes Homebrew, so `shutil.which` alone would miss a correctly
# installed tesseract/poppler. Resolve binaries from PATH first, then the usual
# Homebrew/local prefixes, then an explicit config override — so OCR works in the
# service exactly as it does in a login shell.
_BIN_DIRS = ("/opt/homebrew/bin", "/usr/local/bin", "/opt/local/bin")


def _resolve_bin(name: str, override: str = "") -> str | None:
    if override:
        return override if Path(override).exists() else None
    found = shutil.which(name)
    if found:
        return found
    for d in _BIN_DIRS:
        cand = Path(d) / name
        if cand.exists():
            return str(cand)
    return None


def poppler_bin_dir() -> str | None:
    """Directory holding poppler's ``pdftoppm`` (for pdf2image's ``poppler_path``)
    when it is not on the process PATH; None means "rely on PATH"."""
    p = _resolve_bin("pdftoppm", getattr(config, "POPPLER_BIN", ""))
    return str(Path(p).parent) if p else None


def tesseract_available() -> bool:
    global _available
    if _available is not None:
        return _available
    if config.OCR_ENGINE == "none":
        _available = False
        return False
    try:
        import pytesseract
        from PIL import Image  # noqa: F401
        tpath = _resolve_bin("tesseract", getattr(config, "TESSERACT_CMD", ""))
        if tpath:
            # point pytesseract at the resolved absolute path, so a minimal
            # launchd PATH does not disable OCR that is actually installed.
            pytesseract.pytesseract.tesseract_cmd = tpath
        _available = tpath is not None
    except Exception:
        _available = False
    return _available


def ocr_image(path: str | Path) -> str:
    """Run Tesseract OCR if available; return '' otherwise (VLM covers it)."""
    if config.OCR_ENGINE == "none" or not tesseract_available():
        return ""
    try:
        import pytesseract
        from PIL import Image

        with Image.open(path) as im:
            if im.mode not in ("RGB", "L"):
                im = im.convert("RGB")
            return (pytesseract.image_to_string(im) or "").strip()
    except Exception:
        return ""


def ocr_pdf(path: str | Path, *, max_pages: int | None = None,
            dpi: int | None = None) -> str:
    """OCR a scanned / image-only PDF: rasterize pages with poppler (pdf2image)
    and run Tesseract on each. This is the text-extraction fallback for PDFs
    with no usable text layer (``extractors._extract_pdf``). Returns '' when OCR
    is unavailable or anything goes wrong, so the caller degrades gracefully to
    its prior behaviour. Bounded by ``max_pages`` so a large scan can't hang the
    CPU box. This is OCR (reading printed characters), NOT visual-content
    understanding — a diagram or photo's meaning still needs the vision model."""
    if config.OCR_ENGINE == "none" or not tesseract_available():
        return ""
    max_pages = max_pages or config.PDF_OCR_MAX_PAGES
    dpi = dpi or config.PDF_OCR_DPI
    try:
        from pdf2image import convert_from_path
        import pytesseract

        images = convert_from_path(str(path), dpi=dpi, first_page=1, last_page=max_pages,
                                   poppler_path=poppler_bin_dir())
        pages = []
        for im in images:
            try:
                pages.append((pytesseract.image_to_string(im) or "").strip())
            except Exception:
                pages.append("")
            finally:
                im.close()
        return "\n\n".join(t for t in pages if t).strip()
    except Exception:
        return ""
