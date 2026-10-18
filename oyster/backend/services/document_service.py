import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

import pypdf

import config

UPLOAD_DIR = config.UPLOAD_DIR
METADATA_FILE = config.DOCUMENTS_JSON

UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
METADATA_FILE.parent.mkdir(parents=True, exist_ok=True)

ALLOWED_EXTENSIONS = {".pdf", ".txt"}


def _load_meta() -> dict:
    if METADATA_FILE.exists():
        return json.loads(METADATA_FILE.read_text())
    return {}


def _save_meta(meta: dict) -> None:
    METADATA_FILE.write_text(json.dumps(meta, indent=2))


def list_documents() -> list[dict]:
    return list(_load_meta().values())


def save_upload(filename: str, content: bytes) -> tuple[str, Path]:
    suffix = Path(filename).suffix.lower()
    if suffix not in ALLOWED_EXTENSIONS:
        raise ValueError(
            f"Unsupported file type '{suffix}'. Supported: {sorted(ALLOWED_EXTENSIONS)}"
        )
    doc_id = str(uuid.uuid4())
    dest = UPLOAD_DIR / f"{doc_id}_{filename}"
    dest.write_bytes(content)
    return doc_id, dest


def extract_text(path: Path, filename: str) -> str:
    if filename.lower().endswith(".pdf"):
        reader = pypdf.PdfReader(str(path))
        pages = [page.extract_text() or "" for page in reader.pages]
        return "\n\n".join(pages).strip()
    return path.read_text(encoding="utf-8", errors="ignore").strip()


def register_document(doc_id: str, filename: str, chunk_count: int) -> dict:
    meta = _load_meta()
    record = {
        "id": doc_id,
        "filename": filename,
        "chunk_count": chunk_count,
        "uploaded_at": datetime.now(timezone.utc).isoformat(),
    }
    meta[doc_id] = record
    _save_meta(meta)
    return record
