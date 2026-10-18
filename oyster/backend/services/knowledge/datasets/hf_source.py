"""Read-only HuggingFace Hub / datasets-server client.

Uses the public ``datasets-server.huggingface.co`` REST API (JSON rows over
HTTP via ``httpx``, already a dependency) instead of the ``datasets``/
``huggingface_hub`` Python packages — no new heavy dependency, no local parquet
processing. Every function is best-effort and NEVER raises; network failures
degrade to empty/None so a caller can report "unavailable" honestly rather than
crash.
"""

from __future__ import annotations

import httpx

import config

_HUB_API = "https://huggingface.co/api/datasets/{id}"
_SPLITS_API = "https://datasets-server.huggingface.co/splits?dataset={id}"
_ROWS_API = "https://datasets-server.huggingface.co/rows"


async def health(hf_dataset_id: str) -> dict:
    try:
        async with httpx.AsyncClient(timeout=config.DATASET_NET_TIMEOUT) as client:
            r = await client.get(_HUB_API.format(id=hf_dataset_id))
        if r.status_code == 200:
            return {"available": True, "reason": None}
        return {"available": False, "reason": f"HuggingFace Hub API returned HTTP {r.status_code}"}
    except httpx.HTTPError as e:
        return {"available": False, "reason": f"network error reaching huggingface.co: {type(e).__name__}"}


async def discover_sha(hf_dataset_id: str) -> str | None:
    try:
        async with httpx.AsyncClient(timeout=config.DATASET_NET_TIMEOUT) as client:
            r = await client.get(_HUB_API.format(id=hf_dataset_id))
        if r.status_code != 200:
            return None
        return r.json().get("sha")
    except (httpx.HTTPError, ValueError):
        return None


async def discover_splits(hf_dataset_id: str) -> list[dict]:
    """Returns [{"config": ..., "split": ...}, ...], or [] if undiscoverable."""
    try:
        async with httpx.AsyncClient(timeout=config.DATASET_NET_TIMEOUT) as client:
            r = await client.get(_SPLITS_API.format(id=hf_dataset_id))
        if r.status_code != 200:
            return []
        data = r.json()
        return [{"config": s.get("config"), "split": s.get("split")} for s in data.get("splits", [])
                if s.get("config") and s.get("split")]
    except (httpx.HTTPError, ValueError, KeyError):
        return []


async def fetch_rows(hf_dataset_id: str, config_name: str, split: str, row_limit: int) -> list[dict]:
    """Paginate the datasets-server rows API up to ``row_limit`` rows.

    Returns ``[{"row_index": int, "row": {col: value, ...}}, ...]`` — whatever
    was fetched before any failure (partial results on a mid-stream error).
    """
    out: list[dict] = []
    page_size = config.DATASET_HF_PAGE_SIZE
    offset = 0
    async with httpx.AsyncClient(timeout=config.DATASET_NET_TIMEOUT) as client:
        while len(out) < row_limit:
            length = min(page_size, row_limit - len(out))
            params = {"dataset": hf_dataset_id, "config": config_name, "split": split,
                     "offset": offset, "length": length}
            try:
                r = await client.get(_ROWS_API, params=params)
            except httpx.HTTPError:
                break
            if r.status_code != 200:
                break
            try:
                data = r.json()
            except ValueError:
                break
            rows = data.get("rows", [])
            if not rows:
                break
            for i, item in enumerate(rows):
                out.append({"row_index": item.get("row_idx", offset + i), "row": item.get("row", {})})
            offset += len(rows)
            if len(rows) < length:
                break
    return out
