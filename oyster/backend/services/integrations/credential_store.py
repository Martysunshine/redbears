"""Runtime (process-memory only) credential overrides for the Integrations
settings panel.

Why this exists: the brief asks for a settings panel with real configure/test/
disconnect controls, but this deployment has no secret-manager integration.
Rather than fabricate one, credentials set through the panel are held ONLY in
this process's memory (never written to disk, never logged, never echoed back
to the browser beyond a masked shape) and are lost on restart. They simply
``setattr`` the corresponding ``config`` module attribute, which every adapter
already reads fresh on each call — so an override takes effect immediately and
reverts to the real environment variable's value after a restart.

This is explicitly NOT a substitute for a production secret manager — see
docs/SECURITY.md. A real deployment should set these via environment
variables injected by the host's protected runtime configuration, and this
override endpoint should stay admin-only (it already is — see
routers/integrations.py's mount).

Each adapter exposes a small allowlist of settable field names; anything not
on that list is rejected. Scope-defining fields that gate what an integration
is even ALLOWED to touch — ``DEVIN_ALLOWED_REPOS`` and
``TAVILY_EXCLUDE_DOMAINS`` — are deliberately NOT overridable here: they are a
deploy-time decision, not a per-session credential.
"""
from __future__ import annotations

import config

SETTABLE_FIELDS: dict[str, tuple[str, ...]] = {
    "nemotron_reasoning": ("NEBIUS_API_KEY", "NEBIUS_TOKEN_FACTORY_BASE_URL", "NEMOTRON_REASONING_MODEL"),
    "tavily": ("TAVILY_API_KEY", "TAVILY_BASE_URL"),
    "devin": ("DEVIN_API_KEY", "DEVIN_ORG_ID", "DEVIN_BASE_URL"),
    "opencve": ("OPENCVE_API_TOKEN", "OPENCVE_BASE_URL"),
}

# Which fields are secrets (masked on any read-back) vs. plain config (base
# URL, model id) that is fine to show verbatim.
_SECRET_FIELDS = {"NEBIUS_API_KEY", "TAVILY_API_KEY", "DEVIN_API_KEY", "OPENCVE_API_TOKEN"}


class UnknownField(Exception):
    pass


def set_credentials(integration_id: str, fields: dict[str, str]) -> None:
    allowed = SETTABLE_FIELDS.get(integration_id, ())
    unknown = set(fields) - set(allowed)
    if unknown:
        raise UnknownField(f"Not settable for {integration_id}: {sorted(unknown)}")
    for name, value in fields.items():
        setattr(config, name, value)


def clear_credentials(integration_id: str) -> None:
    for name in SETTABLE_FIELDS.get(integration_id, ()):
        if name in _SECRET_FIELDS:
            setattr(config, name, "")
        # non-secret fields (base URL, model id) are left as-is on "disconnect" —
        # only the credential itself is cleared, so a re-test cleanly reports
        # not_configured rather than silently also forgetting the base URL.
