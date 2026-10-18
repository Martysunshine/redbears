"""The artifact API is open to anonymous visitors, so whatever a record carries
is public. Until 2026-09-14 every listing included ``storage_path`` and
``thumbnail_path`` — absolute server filesystem paths — and a failed extraction
stored the parsing library's own words, which can name a path or a host.

These pin both rules: paths stay out of the public projection, and a failure
is recorded as a sentence for the uploader with the cause kept for the log.
"""

from __future__ import annotations

import pytest

from services.artifacts import extractors, service, store


@pytest.fixture(autouse=True)
def _artifacts_schema():
    store.init_db()
    yield


def test_public_projection_carries_no_filesystem_paths():
    rec = store.create("p-paths", "x.pdf", storage_path="/app/data/artifacts/p-paths/1_x.pdf")

    public = store.get(rec["id"])
    assert "storage_path" not in public
    assert "thumbnail_path" not in public
    assert "/app" not in str(public)

    listed = store.list_for_project("p-paths")[0]
    assert "storage_path" not in listed and "thumbnail_path" not in listed

    # The file/thumbnail routes fetch the paths explicitly, after ownership.
    private = store.get(rec["id"], with_paths=True)
    assert private["storage_path"] == "/app/data/artifacts/p-paths/1_x.pdf"
    assert "thumbnail_path" in private


async def test_extraction_failure_records_a_sentence_not_the_cause(monkeypatch):
    def _boom(path, filename):
        raise extractors.ExtractionError(
            "Could not read this PDF. If it is scanned or encrypted, try a text export."
        ) from RuntimeError("/app/data/artifacts/p-x/1_x.pdf: EOF marker not found")

    monkeypatch.setattr(extractors, "extract", _boom)
    rec = await service.ingest_file("p-x", "x.pdf", b"%PDF-1.4 garbage")

    assert rec["status"] == "failed"
    assert rec["error"].startswith("Could not read this PDF")
    assert "/app" not in rec["error"]
    assert "EOF marker" not in rec["error"]
    assert "storage_path" not in rec


def test_real_extractor_never_echoes_library_text(tmp_path):
    bad = tmp_path / "broken.pdf"
    bad.write_bytes(b"this is not a pdf")
    with pytest.raises(extractors.ExtractionError) as excinfo:
        extractors.extract(bad, "broken.pdf")
    message = str(excinfo.value)
    for forbidden in ("pypdf", "EOF", "Traceback", str(tmp_path)):
        assert forbidden not in message, message
    assert excinfo.value.__cause__ is not None
