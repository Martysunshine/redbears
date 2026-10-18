"""Document + image readability: text PDF, scanned (image-only) PDF, DOCX, and
image OCR, each with known synthetic content. Guards the 2026-10-07 fix that
adds a Tesseract/poppler OCR fallback for scanned PDFs and dedicated image OCR.

Tesseract-dependent cases skip cleanly where the binary is absent, so the suite
still passes on a host without OCR installed.
"""
from __future__ import annotations

import pytest
from PIL import Image, ImageDraw

import config
from services.artifacts import extractors
from services.media import ocr

_HAS_TESS = ocr.tesseract_available()
_needs_ocr = pytest.mark.skipif(not _HAS_TESS, reason="tesseract not installed")


def _text_pdf(path, text):
    from fpdf import FPDF
    pdf = FPDF(); pdf.add_page(); pdf.set_font("Helvetica", size=16)
    pdf.multi_cell(0, 10, text)
    pdf.output(str(path))


def _scanned_pdf(path, text):
    img = Image.new("RGB", (1240, 700), "white")
    ImageDraw.Draw(img).text((60, 80), text, fill="black")
    # scale up so default-font text is large enough for OCR
    img = img.resize((2480, 1400))
    img.save(path, "PDF", resolution=150)  # image-only: no text layer


def _image_png(path, text):
    img = Image.new("RGB", (1200, 300), "white")
    ImageDraw.Draw(img).text((40, 120), text, fill="black")
    img = img.resize((2400, 600))
    img.save(path)


def test_text_pdf_extracts_via_text_layer(tmp_path):
    p = tmp_path / "t.pdf"
    _text_pdf(p, "ALPHA-TEXTPDF vsftpd 2.3.4 marker line one two three")
    assert "ALPHA-TEXTPDF" in extractors.extract(p, "t.pdf")


def test_docx_extracts(tmp_path):
    import docx
    p = tmp_path / "d.docx"
    doc = docx.Document(); doc.add_paragraph("BETA-DOCX kerberoasting marker"); doc.save(str(p))
    assert "BETA-DOCX" in extractors.extract(p, "d.docx")


@_needs_ocr
def test_scanned_pdf_falls_back_to_ocr(tmp_path):
    p = tmp_path / "scan.pdf"
    _scanned_pdf(p, "GAMMA SCANPDF CVE MARKER TEXT")
    out = extractors.extract(p, "scan.pdf")
    assert "GAMMA" in out and "SCANPDF" in out


@_needs_ocr
def test_image_ocr_reads_text(tmp_path):
    p = tmp_path / "shot.png"
    _image_png(p, "DELTA SCREENSHOT MARKER")
    out = ocr.ocr_image(p)
    assert "DELTA" in out and "SCREENSHOT" in out


def test_ocr_disabled_is_graceful(tmp_path, monkeypatch):
    """OCR_ENGINE=none => fallbacks return '' and a scanned PDF raises the honest
    'no extractable text', never a crash."""
    monkeypatch.setattr(config, "OCR_ENGINE", "none")
    monkeypatch.setattr(ocr, "_available", None)
    p = tmp_path / "scan.pdf"
    _scanned_pdf(p, "EPSILON NOOCR MARKER")
    assert ocr.ocr_pdf(p) == ""
    assert ocr.ocr_image(p) == ""
    with pytest.raises(extractors.ExtractionError):
        extractors.extract(p, "scan.pdf")
    monkeypatch.setattr(ocr, "_available", None)  # reset cache for other tests
