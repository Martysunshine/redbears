"""The background Ollama prober: its state machine, and that it never leaks a URL.

Runs under pytest (asyncio_mode = auto). The prober itself is never started;
probe_once() is driven by hand with a fake httpx client.
"""
from __future__ import annotations

import json

import pytest

import config
from services import ollama_probe as probe

PRIMARY = "http://minipc:11434"
FALLBACK = "http://local:11434"


class _Resp:
    def __init__(self, status: int, models: list[str] | None = None):
        self.status_code = status
        self._models = models or []

    def json(self):
        return {"models": [{"name": m} for m in self._models]}


class FakeClient:
    """GETs succeed only for hosts in `up`; everything else raises."""

    def __init__(self, up: set[str]):
        self.up = up
        self.calls: list[str] = []

    async def get(self, url: str):
        self.calls.append(url)
        if any(h in url for h in self.up):
            return _Resp(200, ["llama3.2:3b"])
        raise ConnectionError("blackholed")


@pytest.fixture(autouse=True)
def _two_endpoints(monkeypatch):
    monkeypatch.setattr(config, "OLLAMA_GENERATE_URL", f"{PRIMARY}/api/generate")
    monkeypatch.setattr(config, "OLLAMA_FALLBACK_GENERATE_URL", f"{FALLBACK}/api/generate")
    monkeypatch.setattr(config, "OLLAMA_PROBE_FAILS_TO_DOWN", 2)
    monkeypatch.setattr(config, "OLLAMA_PROBE_DOWN_INTERVAL_S", 60)
    probe.reset_for_tests()
    yield
    probe.reset_for_tests()


async def test_no_opinion_until_the_first_round():
    assert probe.has_data() is False
    assert probe.ordered() is None
    assert probe.live_via() is None


async def test_primary_goes_down_after_consecutive_failures_and_fallback_leads():
    client = FakeClient(up={"local"})
    await probe.probe_once(client)                 # failure 1: not yet down
    assert probe.state_for(f"{PRIMARY}/api/generate").reachable is None
    assert probe.ordered() is None                 # primary still unknown
    await probe.probe_once(client)                 # failure 2: down
    assert probe.state_for(f"{PRIMARY}/api/generate").reachable is False
    assert probe.ordered() == [f"{FALLBACK}/api/generate", f"{PRIMARY}/api/generate"]
    assert probe.live_via() == "fallback"


async def test_one_success_brings_the_primary_back():
    client = FakeClient(up={"local"})
    await probe.probe_once(client)
    await probe.probe_once(client)
    assert probe.live_via() == "fallback"
    client.up = {"minipc", "local"}
    # A down endpoint is only re-probed every PROBE_DOWN_INTERVAL_S — force it.
    probe.state_for(f"{PRIMARY}/api/generate").last_probe = None
    await probe.probe_once(client)
    assert probe.ordered() == [f"{PRIMARY}/api/generate", f"{FALLBACK}/api/generate"]
    assert probe.live_via() == "primary"


async def test_a_down_endpoint_is_not_hammered_every_round():
    client = FakeClient(up={"local"})
    await probe.probe_once(client)
    await probe.probe_once(client)
    n = len([c for c in client.calls if "minipc" in c])
    await probe.probe_once(client)
    await probe.probe_once(client)
    assert len([c for c in client.calls if "minipc" in c]) == n   # skipped while down


async def test_request_time_marks_flip_state_at_once():
    probe.simulate_tick_for_tests()
    probe.mark_failed(f"{PRIMARY}/api/generate")
    assert probe.ordered()[0] == f"{FALLBACK}/api/generate"
    probe.mark_ok(f"{PRIMARY}/api/generate")
    assert probe.ordered()[0] == f"{PRIMARY}/api/generate"


async def test_snapshot_never_contains_a_url_or_port():
    client = FakeClient(up={"local"})
    await probe.probe_once(client)
    text = json.dumps(probe.snapshot())
    assert "http" not in text and "11434" not in text and "minipc" not in text
    assert set(json.loads(text)["endpoints"]) == {"primary", "fallback"}
