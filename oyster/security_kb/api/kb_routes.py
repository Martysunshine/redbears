"""FastAPI router — security KB query endpoints.

Mount this in main.py:
    from security_kb.api.kb_routes import router as kb_router
    app.include_router(kb_router, prefix="/kb", tags=["security-kb"])
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Annotated

from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel, Field

# resolve imports whether called from within security_kb or from the Oyster backend
_KB_ROOT = Path(__file__).parents[1]
if str(_KB_ROOT) not in sys.path:
    sys.path.insert(0, str(_KB_ROOT))

from scripts.pipeline.embed import query as kb_query, collection_stats

router = APIRouter()


# ── request / response models ─────────────────────────────────────────────────

class KBSearchRequest(BaseModel):
    query: str = Field(..., min_length=3, description="Natural-language search query")
    top_k: int = Field(8, ge=1, le=30, description="Number of results to return")
    category: str | None = Field(None, description="Filter by category (owasp, tools, labs, writeups, ai_security)")
    attack_type: str | None = Field(None, description="Filter by attack type keyword (sqli, xss, rce, …)")
    min_score: float = Field(0.30, ge=0.0, le=1.0, description="Minimum relevance score")


class KBResult(BaseModel):
    text: str
    score: float
    source: str
    category: str
    tool: str
    attack_type: str
    tags: str


class KBSearchResponse(BaseModel):
    query: str
    total: int
    results: list[KBResult]


class KBPromptResponse(BaseModel):
    query: str
    context: str
    result_count: int


class KBStatsResponse(BaseModel):
    collection: str
    total_documents: int


# ── helpers ────────────────────────────────────────────────────────────────────

def _build_where(category: str | None, attack_type: str | None) -> dict | None:
    conditions: list[dict] = []
    if category:
        conditions.append({"category": {"$eq": category}})
    if attack_type:
        # tags is a comma-separated string — use $contains
        conditions.append({"tags": {"$contains": attack_type}})
    if not conditions:
        return None
    if len(conditions) == 1:
        return conditions[0]
    return {"$and": conditions}


# ── routes ────────────────────────────────────────────────────────────────────

@router.post("/search", response_model=KBSearchResponse, summary="Semantic KB search")
async def search(req: KBSearchRequest) -> KBSearchResponse:
    """Search the security knowledge base with semantic similarity + optional filters."""
    where = _build_where(req.category, req.attack_type)
    try:
        raw = kb_query(req.query, top_k=req.top_k, where=where)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"KB query error: {e}") from e

    results = [
        KBResult(
            text=r["text"],
            score=r["score"],
            source=r["metadata"].get("source", ""),
            category=r["metadata"].get("category", ""),
            tool=r["metadata"].get("tool", ""),
            attack_type=r["metadata"].get("attack_type", ""),
            tags=r["metadata"].get("tags", ""),
        )
        for r in raw
        if r["score"] >= req.min_score
    ]

    return KBSearchResponse(query=req.query, total=len(results), results=results)


@router.post("/prompt-context", response_model=KBPromptResponse, summary="Retrieve KB context for LLM prompts")
async def prompt_context(req: KBSearchRequest) -> KBPromptResponse:
    """Return a pre-formatted context block ready to be injected into an LLM prompt."""
    where = _build_where(req.category, req.attack_type)
    try:
        raw = kb_query(req.query, top_k=req.top_k, where=where)
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"KB query error: {e}") from e

    filtered = [r for r in raw if r["score"] >= req.min_score]

    parts: list[str] = []
    for i, r in enumerate(filtered, 1):
        src = Path(r["metadata"].get("source", "unknown")).name
        score = r["score"]
        parts.append(f"[{i}] Source: {src} (score: {score:.2f})\n{r['text']}")

    context = "\n\n---\n\n".join(parts) if parts else "No relevant context found."

    return KBPromptResponse(
        query=req.query,
        context=context,
        result_count=len(filtered),
    )


@router.get("/stats", response_model=KBStatsResponse, summary="KB collection statistics")
async def stats() -> KBStatsResponse:
    try:
        s = collection_stats()
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Stats error: {e}") from e
    return KBStatsResponse(collection=s["name"], total_documents=s["count"])


@router.get("/categories", summary="List available filter categories")
async def list_categories() -> dict:
    return {
        "categories": ["owasp", "tools", "labs", "writeups", "ai_security"],
        "attack_types": [
            "sqli", "xss", "ssrf", "xxe", "idor", "rce", "auth",
            "api", "crypto", "lfi", "rfi", "csrf", "deserialization",
            "misconfig", "llm",
        ],
    }
