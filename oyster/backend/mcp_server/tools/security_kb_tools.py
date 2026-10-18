from __future__ import annotations

from services import rag_service


async def search_security_kb(query: str, top_k: int = 5) -> dict:
    try:
        results = await rag_service.search_async(query, top_k=top_k)
        return {"query": query, "results": results, "total": len(results)}
    except Exception as exc:
        return {"error": f"search_security_kb failed: {exc}"}


async def get_security_context(topic: str, top_k: int = 3) -> dict:
    try:
        results = await rag_service.search_async(f"security {topic}", top_k=top_k)
        context = "\n\n".join(
            f"[{i}] {r['document']}:\n{r['chunk']}"
            for i, r in enumerate(results, 1)
        )
        return {"topic": topic, "context": context, "sources": len(results)}
    except Exception as exc:
        return {"error": f"get_security_context failed: {exc}"}
