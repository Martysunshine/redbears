from __future__ import annotations

from fastapi import APIRouter, HTTPException

from models.schemas import DocumentSearchRequest
from services import rag_service

router = APIRouter(tags=["documents"])


@router.post("/documents/search")
async def search_documents(request: DocumentSearchRequest):
    results = await rag_service.search_async(request.query, top_k=request.top_k)
    if not results:
        raise HTTPException(
            status_code=404,
            detail="No documents in the knowledge base.",
        )
    return {"results": results, "query": request.query, "total": len(results)}
