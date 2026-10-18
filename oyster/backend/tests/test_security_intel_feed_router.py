"""The Security Intel feed router must pick OpenCVE when a token is
configured and fall back to the CISA KEV feed otherwise — never attempt an
OpenCVE call that's certain to 401."""
from __future__ import annotations

import config
from routers import security_intel_feed
from services.intel import kev_feed, opencve_feed


def test_falls_back_to_kev_when_opencve_has_no_token(monkeypatch):
    monkeypatch.setattr(config, "OPENCVE_API_TOKEN", "")
    assert security_intel_feed._active() is kev_feed


def test_uses_opencve_when_a_token_is_configured(monkeypatch):
    monkeypatch.setattr(config, "OPENCVE_API_TOKEN", "opc_org.test.secret")
    assert security_intel_feed._active() is opencve_feed
