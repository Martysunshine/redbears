"""Embedding pipeline — encode chunks and upsert into ChromaDB."""

from __future__ import annotations

import hashlib
import logging
from pathlib import Path
from typing import Iterable

import chromadb
from chromadb.config import Settings
from sentence_transformers import SentenceTransformer
from tqdm import tqdm

# resolved at import time so the module is usable standalone
import sys
sys.path.insert(0, str(Path(__file__).parents[3]))
from config import (
    EMBEDDING_MODEL,
    COLLECTION_NAME,
    VECTOR_STORE_DIR,
    BATCH_SIZE,
)

log = logging.getLogger(__name__)

_model: SentenceTransformer | None = None
_client: chromadb.PersistentClient | None = None
_collection = None


def _get_model() -> SentenceTransformer:
    global _model
    if _model is None:
        log.info("Loading embedding model %s …", EMBEDDING_MODEL)
        _model = SentenceTransformer(EMBEDDING_MODEL)
    return _model


def _get_collection():
    global _client, _collection
    if _collection is None:
        VECTOR_STORE_DIR.mkdir(parents=True, exist_ok=True)
        _client = chromadb.PersistentClient(
            path=str(VECTOR_STORE_DIR),
            settings=Settings(anonymized_telemetry=False),
        )
        _collection = _client.get_or_create_collection(
            name=COLLECTION_NAME,
            metadata={"hnsw:space": "cosine"},
        )
    return _collection


def _chunk_id(text: str, source: str, index: int) -> str:
    payload = f"{source}::{index}::{text[:120]}"
    return hashlib.sha256(payload.encode()).hexdigest()[:32]


def upsert_chunks(
    chunks: list[str],
    metadatas: list[dict],
    *,
    show_progress: bool = False,
) -> int:
    """Encode `chunks`, attach `metadatas`, upsert into ChromaDB.
    Returns the number of documents upserted."""
    if not chunks:
        return 0

    model = _get_model()
    collection = _get_collection()

    total = 0
    batches = range(0, len(chunks), BATCH_SIZE)
    if show_progress:
        batches = tqdm(batches, desc="Embedding", unit="batch")

    for start in batches:
        batch_texts = chunks[start : start + BATCH_SIZE]
        batch_meta  = metadatas[start : start + BATCH_SIZE]

        embeddings = model.encode(batch_texts, normalize_embeddings=True).tolist()
        ids = [
            _chunk_id(t, m.get("source", ""), m.get("chunk_index", i))
            for i, (t, m) in enumerate(zip(batch_texts, batch_meta), start)
        ]

        collection.upsert(
            ids=ids,
            documents=batch_texts,
            embeddings=embeddings,
            metadatas=batch_meta,
        )
        total += len(batch_texts)

    return total


def query(
    text: str,
    *,
    top_k: int = 8,
    where: dict | None = None,
) -> list[dict]:
    """Semantic search. Returns list of {text, score, metadata}."""
    model = _get_model()
    collection = _get_collection()

    embedding = model.encode([text], normalize_embeddings=True).tolist()
    kwargs: dict = {"query_embeddings": embedding, "n_results": top_k, "include": ["documents", "metadatas", "distances"]}
    if where:
        kwargs["where"] = where

    results = collection.query(**kwargs)

    out: list[dict] = []
    for doc, meta, dist in zip(
        results["documents"][0],
        results["metadatas"][0],
        results["distances"][0],
    ):
        out.append({
            "text": doc,
            "score": round(max(0.0, 1.0 - dist), 4),
            "metadata": meta,
        })
    return out


def collection_stats() -> dict:
    c = _get_collection()
    return {"count": c.count(), "name": COLLECTION_NAME}
