"""Evidence reranking with NVIDIA llama-nemotron-rerank-1b-v2.

Role: a cross-encoder that rescores (query, passage) pairs for passages the
existing hybrid retrieval already found. It decides which passages reach the
answer model and in what order. It does not generate text.

Wire format: the NVIDIA NIM reranking API, ``POST /v1/ranking``
    {"model", "query": {"text"}, "passages": [{"text"}], "truncate"}
 -> {"rankings": [{"index", "logit"}, ...], "usage": {...}}

Identity is positional: the response ``index`` points into the list we sent, and
we re-attach scores to the ORIGINAL citation dicts, so chunk_id, source_url,
pack and every other provenance field survive untouched.

Every failure (disabled, missing credentials, timeout, HTTP error, malformed
response) returns the input order plus a status that says why. Callers must
surface that status; never present a fallback as a rerank.
"""
from __future__ import annotations

import datetime
import time
from urllib.parse import urlparse

import httpx

import config
import log_config


def _kind(url: str) -> str:
    host = (urlparse(url).hostname or "").lower()
    if host in ("127.0.0.1", "localhost", "::1"):
        return "local"
    if host.endswith("nvidia.com"):
        return "nvidia-hosted"
    return "remote"


_budget = {"day": None, "calls": 0}


def _take_budget(kind: str) -> bool:
    """Daily call cap for non-local endpoints (they can be metered/billed)."""
    if kind == "local":
        return True
    today = datetime.datetime.now(datetime.timezone.utc).date()
    if _budget["day"] != today:
        _budget.update(day=today, calls=0)
    if _budget["calls"] >= config.NEMOTRON_RERANK_DAILY_CALL_LIMIT:
        return False
    _budget["calls"] += 1
    return True


def _info(**kw) -> dict:
    base = {
        "requested": True,
        "status": "fell_back",          # "ran" | "fell_back" | "disabled"
        "reason": None,
        "model": config.NEMOTRON_RERANK_MODEL,
        "endpoint": _kind(config.NEMOTRON_RERANK_URL),
        "latency_ms": None,
        "candidates": 0,
        "returned": 0,
        "order_changed": False,
    }
    base.update(kw)
    return base


async def rerank(query: str, candidates: list[dict], top_k: int) -> tuple[list[dict], dict]:
    """Return (selected citations in reranked order, info). On any failure the
    selection is simply ``candidates[:top_k]`` in their existing order."""
    fallback = candidates[:top_k]
    n = len(candidates)

    if not config.NEMOTRON_RERANK_ENABLED:
        return fallback, _info(status="disabled", reason="reranking disabled by configuration",
                               candidates=n, returned=len(fallback))
    if n == 0:
        return fallback, _info(status="fell_back", reason="no candidates", candidates=0)

    url = config.NEMOTRON_RERANK_URL
    kind = _kind(url)
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    # Credential scoping: the NVIDIA key goes ONLY to *.nvidia.com; any other
    # endpoint gets its own, separate token (or none).
    token = config.NEMOTRON_RERANK_API_KEY or (config.NVIDIA_API_KEY if kind == "nvidia-hosted" else "")
    if token:
        headers["Authorization"] = f"Bearer {token}"
    elif kind == "nvidia-hosted":
        # Do not even send the request: it cannot succeed and would only add latency.
        return fallback, _info(reason="NVIDIA_API_KEY is not set for the NVIDIA-hosted endpoint",
                               candidates=n, returned=len(fallback))
    if not _take_budget(kind):
        return fallback, _info(reason="daily rerank call budget reached for the remote endpoint",
                               candidates=n, returned=len(fallback))

    cap = config.NEMOTRON_RERANK_PASSAGE_CHARS
    body = {
        "model": config.NEMOTRON_RERANK_MODEL,
        "query": {"text": query},
        "passages": [{"text": (c.get("chunk") or c.get("content") or "")[:cap]} for c in candidates],
        "truncate": "END",
    }
    started = time.perf_counter()
    try:
        async with httpx.AsyncClient(timeout=config.NEMOTRON_RERANK_TIMEOUT_S) as client:
            resp = await client.post(url, json=body, headers=headers)
        ms = int((time.perf_counter() - started) * 1000)
        if resp.status_code != 200:
            return fallback, _info(reason=f"reranker returned HTTP {resp.status_code}", latency_ms=ms,
                                   candidates=n, returned=len(fallback))
        rankings = resp.json().get("rankings")
        idx = [r["index"] for r in rankings]
        logits = {r["index"]: float(r["logit"]) for r in rankings}
        if (not idx or len(set(idx)) != len(idx)
                or any((not isinstance(i, int)) or i < 0 or i >= n for i in idx)):
            raise ValueError("rankings do not index the submitted passages")
    except httpx.TimeoutException:
        ms = int((time.perf_counter() - started) * 1000)
        return fallback, _info(reason=f"reranker timed out after {config.NEMOTRON_RERANK_TIMEOUT_S:g}s",
                               latency_ms=ms, candidates=n, returned=len(fallback))
    except (httpx.HTTPError, ValueError, KeyError, TypeError) as exc:
        ms = int((time.perf_counter() - started) * 1000)
        log_config.error("rerank.failed", "nemotron rerank failed", {"error": type(exc).__name__})
        return fallback, _info(reason=f"reranker unavailable ({type(exc).__name__})", latency_ms=ms,
                               candidates=n, returned=len(fallback))

    order = sorted(idx, key=lambda i: logits[i], reverse=True)[:top_k]
    selected: list[dict] = []
    for new_rank, i in enumerate(order):
        c = dict(candidates[i])
        c["rerank_score"] = round(logits[i], 4)
        c["retrieval_rank"] = i + 1      # 1-based position before reranking
        selected.append(c)
    return selected, _info(status="ran", latency_ms=ms, candidates=n, returned=len(selected),
                           order_changed=order != list(range(len(order))))
