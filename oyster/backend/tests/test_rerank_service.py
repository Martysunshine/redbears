"""Nemotron rerank: ordering is applied, provenance rides along, every failure
falls back to the existing order and says why."""
import asyncio

import httpx
import pytest

import config
from services import rerank_service


def _cands(n=4):
    return [{"n": i + 1, "chunk_id": f"id{i}", "chunk": f"passage {i}", "source_url": f"http://x/{i}",
             "knowledge_pack": "p", "score": 0.1} for i in range(n)]


class _Client:
    """Stand-in for httpx.AsyncClient driven by a handler(request_json)->response."""
    handler = None
    seen = None

    def __init__(self, *a, **k): pass
    async def __aenter__(self): return self
    async def __aexit__(self, *a): return False

    async def post(self, url, json=None, headers=None):
        _Client.seen = {"url": url, "json": json, "headers": headers}
        return _Client.handler(json)


def _resp(status, body):
    return httpx.Response(status, json=body)


@pytest.fixture(autouse=True)
def _cfg(monkeypatch):
    monkeypatch.setattr(rerank_service.httpx, "AsyncClient", _Client)
    monkeypatch.setattr(config, "NEMOTRON_RERANK_ENABLED", True)
    monkeypatch.setattr(config, "NEMOTRON_RERANK_URL", "http://127.0.0.1:8110/v1/ranking")
    monkeypatch.setattr(config, "NVIDIA_API_KEY", "")


def run(coro):
    return asyncio.run(coro)


def test_order_applied_and_metadata_preserved():
    _Client.handler = lambda j: _resp(200, {"rankings": [
        {"index": 2, "logit": 9.0}, {"index": 0, "logit": 1.0}, {"index": 3, "logit": -2.0}, {"index": 1, "logit": -5.0}]})
    out, info = run(rerank_service.rerank("q", _cands(), 2))
    assert [c["chunk_id"] for c in out] == ["id2", "id0"]
    assert out[0]["source_url"] == "http://x/2" and out[0]["knowledge_pack"] == "p"
    assert out[0]["rerank_score"] == 9.0 and out[0]["retrieval_rank"] == 3
    assert info["status"] == "ran" and info["order_changed"] is True and info["returned"] == 2
    # NIM schema on the wire
    body = _Client.seen["json"]
    assert body["query"] == {"text": "q"} and len(body["passages"]) == 4
    assert body["passages"][2] == {"text": "passage 2"} and body["model"] == config.NEMOTRON_RERANK_MODEL
    assert "Authorization" not in _Client.seen["headers"]


def test_nvidia_key_goes_only_to_nvidia_hosts(monkeypatch):
    monkeypatch.setattr(config, "NVIDIA_API_KEY", "nvapi-test")
    _Client.handler = lambda j: _resp(200, {"rankings": [{"index": 0, "logit": 1.0}]})
    run(rerank_service.rerank("q", _cands(1), 1))                       # local URL
    assert "Authorization" not in _Client.seen["headers"]
    monkeypatch.setattr(config, "NEMOTRON_RERANK_URL", "https://rerank.other.example/v1/ranking")
    run(rerank_service.rerank("q", _cands(1), 1))                       # third-party URL
    assert "Authorization" not in _Client.seen["headers"]
    monkeypatch.setattr(config, "NEMOTRON_RERANK_URL", "https://ai.api.nvidia.com/v1/ranking")
    run(rerank_service.rerank("q", _cands(1), 1))                       # NVIDIA host
    assert _Client.seen["headers"]["Authorization"] == "Bearer nvapi-test"


def test_separate_endpoint_token_and_daily_budget(monkeypatch):
    monkeypatch.setattr(config, "NEMOTRON_RERANK_URL", "https://rerank.other.example/v1/ranking")
    monkeypatch.setattr(config, "NEMOTRON_RERANK_API_KEY", "tok")
    monkeypatch.setattr(config, "NEMOTRON_RERANK_DAILY_CALL_LIMIT", 2)
    rerank_service._budget.update(day=None, calls=0)
    _Client.handler = lambda j: _resp(200, {"rankings": [{"index": 0, "logit": 1.0}]})
    for _ in range(2):
        _, info = run(rerank_service.rerank("q", _cands(1), 1))
        assert info["status"] == "ran"
    assert _Client.seen["headers"]["Authorization"] == "Bearer tok"
    _Client.seen = None
    out, info = run(rerank_service.rerank("q", _cands(2), 1))
    assert info["status"] == "fell_back" and "budget" in info["reason"] and _Client.seen is None


def test_missing_credentials_for_hosted_endpoint_falls_back_without_request(monkeypatch):
    monkeypatch.setattr(config, "NEMOTRON_RERANK_URL",
                        "https://ai.api.nvidia.com/v1/retrieval/nvidia/reranking")
    _Client.seen = None
    out, info = run(rerank_service.rerank("q", _cands(), 3))
    assert [c["chunk_id"] for c in out] == ["id0", "id1", "id2"]
    assert info["status"] == "fell_back" and "NVIDIA_API_KEY" in info["reason"]
    assert info["endpoint"] == "nvidia-hosted" and _Client.seen is None


@pytest.mark.parametrize("handler,needle", [
    (lambda j: _resp(500, {}), "HTTP 500"),
    (lambda j: _resp(200, {"rankings": [{"index": 9, "logit": 1.0}]}), "unavailable"),
    (lambda j: _resp(200, {"rankings": [{"index": 0, "logit": 1}, {"index": 0, "logit": 2}]}), "unavailable"),
    (lambda j: _resp(200, {"nope": 1}), "unavailable"),
])
def test_bad_responses_fall_back(handler, needle):
    _Client.handler = handler
    out, info = run(rerank_service.rerank("q", _cands(), 2))
    assert [c["chunk_id"] for c in out] == ["id0", "id1"]
    assert info["status"] == "fell_back" and needle in info["reason"]
    assert "rerank_score" not in out[0]


def test_timeout_and_connect_error_fall_back():
    def boom(exc):
        def h(j): raise exc
        return h
    for exc, needle in ((httpx.ReadTimeout("t"), "timed out"), (httpx.ConnectError("c"), "unavailable")):
        _Client.handler = boom(exc)
        out, info = run(rerank_service.rerank("q", _cands(), 2))
        assert [c["chunk_id"] for c in out] == ["id0", "id1"]
        assert info["status"] == "fell_back" and needle in info["reason"]


def test_disabled(monkeypatch):
    monkeypatch.setattr(config, "NEMOTRON_RERANK_ENABLED", False)
    _, info = run(rerank_service.rerank("q", _cands(), 2))
    assert info["status"] == "disabled"


def test_knowledge_ask_rate_limit(monkeypatch):
    from fastapi import HTTPException
    from routers import knowledge as k

    class Req:
        headers = {"authorization": "Bearer abc"}
        client = None

    monkeypatch.setattr(config, "KNOWLEDGE_STREAM_RATE_PER_MIN", 2)
    k._ask_hits.clear()
    k._rate_limit_ask(Req()); k._rate_limit_ask(Req())
    with pytest.raises(HTTPException) as e:
        k._rate_limit_ask(Req())
    assert e.value.status_code == 429 and "Retry-After" in e.value.headers
