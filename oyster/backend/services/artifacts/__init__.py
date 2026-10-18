"""Unified artifact ingestion — project-scoped uploads (files, folders, notes).

Extends the existing RAG pipeline (``rag_service``) rather than creating a second
upload system: every artifact's text is chunked + embedded into the one ChromaDB
collection, tagged with ``project_id`` + ``artifact_id`` for scoping and retrieval.
"""

from . import extractors, service, store  # noqa: F401
