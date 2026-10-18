"""Local serving of nvidia/llama-nemotron-rerank-1b-v2 behind the NVIDIA NIM
reranking schema (POST /v1/ranking), so Oyster talks to one documented API
whether the reranker is this process or a real NIM.

Request : {"model": str, "query": {"text": str}, "passages": [{"text": str}], "truncate": "NONE"|"END"}
Response: {"rankings": [{"index": int, "logit": float}, ...] (descending logit), "usage": {...}}

The model is a cross-encoder (Llama-3.2-1B, bidirectional attention, avg pool,
1 logit head). Input format is the one on the model card:
    "question:{q} \n \n passage:{p}"
"""
from __future__ import annotations

import os
import threading
import time

import hmac

import torch
from fastapi import FastAPI, Header, HTTPException
from pydantic import BaseModel, Field
from transformers import AutoModelForSequenceClassification, AutoTokenizer

MODEL_ID = os.getenv("RERANK_MODEL_ID", "nvidia/llama-nemotron-rerank-1b-v2")
# Pinned upstream revision (HF commit sha). Override only deliberately.
REVISION = os.getenv("RERANK_MODEL_REVISION", "828765652b05bd439c9789d2a6d093db1caa1443")
CACHE_DIR = os.getenv("RERANK_CACHE_DIR", os.path.expanduser("~/redbears-assets/models/hf"))
MAX_LENGTH = int(os.getenv("RERANK_MAX_LENGTH", "512"))   # model supports 8192; 512 keeps latency low
BATCH = int(os.getenv("RERANK_BATCH", "8"))
DEVICE = os.getenv("RERANK_DEVICE") or ("mps" if torch.backends.mps.is_available() else "cpu")

# Optional shared secret. Unset = open, which is only acceptable while bound to
# 127.0.0.1 (start.sh does that). Set it before binding any other interface.
TOKEN = os.getenv("RERANK_SERVER_TOKEN", "")

app = FastAPI(title="Nemotron reranker (local)", docs_url=None, redoc_url=None, openapi_url=None)


def _auth(authorization: str | None) -> None:
    if TOKEN and not hmac.compare_digest(authorization or "", f"Bearer {TOKEN}"):
        raise HTTPException(401, "unauthorized")
_lock = threading.Lock()
_state: dict = {"ready": False, "error": None, "load_s": None}


def _load() -> None:
    t0 = time.time()
    try:
        tok = AutoTokenizer.from_pretrained(MODEL_ID, revision=REVISION, cache_dir=CACHE_DIR,
                                            trust_remote_code=True, padding_side="left")
        if tok.pad_token is None:
            tok.pad_token = tok.eos_token
        model = AutoModelForSequenceClassification.from_pretrained(
            MODEL_ID, revision=REVISION, cache_dir=CACHE_DIR, trust_remote_code=True,
            torch_dtype=torch.bfloat16).eval()
        if model.config.pad_token_id is None:
            model.config.pad_token_id = tok.eos_token_id
        model.to(DEVICE)
        _state.update(tok=tok, model=model, ready=True, load_s=round(time.time() - t0, 1))
    except Exception as exc:  # surfaced via /v1/health/ready
        _state["error"] = f"{type(exc).__name__}: {exc}"


threading.Thread(target=_load, daemon=True).start()


class Text(BaseModel):
    text: str


class RankRequest(BaseModel):
    model: str = MODEL_ID
    query: Text
    passages: list[Text] = Field(min_length=1, max_length=256)
    truncate: str = "END"


@app.get("/v1/health/ready")
def ready():
    if _state["ready"]:
        return {"ready": True, "model": MODEL_ID, "revision": REVISION, "device": DEVICE,
                "load_s": _state["load_s"]}
    raise HTTPException(503, _state["error"] or "loading")


@app.get("/v1/models")
def models(authorization: str | None = Header(default=None)):
    _auth(authorization)
    return {"data": [{"id": MODEL_ID, "revision": REVISION}]}


@app.post("/v1/ranking")
def ranking(req: RankRequest, authorization: str | None = Header(default=None)):
    _auth(authorization)
    if not _state["ready"]:
        raise HTTPException(503, _state["error"] or "model still loading")
    tok, model = _state["tok"], _state["model"]
    texts = [f"question:{req.query.text} \n \n passage:{p.text}" for p in req.passages]
    scores: list[float] = []
    n_tokens = 0
    with _lock, torch.inference_mode():
        for i in range(0, len(texts), BATCH):
            b = tok(texts[i:i + BATCH], padding=True, truncation=(req.truncate != "NONE"),
                    return_tensors="pt", max_length=MAX_LENGTH)
            n_tokens += int(b["attention_mask"].sum())
            b = {k: v.to(DEVICE) for k, v in b.items()}
            scores += model(**b).logits.view(-1).float().cpu().tolist()
    order = sorted(range(len(scores)), key=lambda i: scores[i], reverse=True)
    return {"rankings": [{"index": i, "logit": scores[i]} for i in order],
            "usage": {"prompt_tokens": n_tokens, "total_tokens": n_tokens}}
