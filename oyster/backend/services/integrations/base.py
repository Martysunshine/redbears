"""Common contract for third-party integration adapters (Nemotron reasoning via
Nebius Token Factory, Tavily, Devin).

Each adapter owns its own provider-specific request/response schema; this module
owns only what is common across all of them: configuration (credentials read
once, server-side, never echoed back), a real connection check, a bounded call
with timeout + cancellation, and one shared status vocabulary so the UI can
render "Connected / Not configured / Unavailable" the same way for every
integration without knowing its wire format.

Nothing here simulates success. ``check_connection`` always makes (or honestly
skips) a real network call; a missing credential returns NOT_CONFIGURED before
any request is sent, and a request that fails returns UNAVAILABLE with a
sanitised reason. There is no code path that returns CONNECTED without a real
2xx from the provider.
"""
from __future__ import annotations

import abc
import asyncio
import dataclasses
import enum
import re
import time


class IntegrationStatus(str, enum.Enum):
    NOT_CONFIGURED = "not_configured"  # no credential / base URL set
    CONNECTED = "connected"            # last real check succeeded
    UNAVAILABLE = "unavailable"        # configured, but the last real check failed
    CHECKING = "checking"              # a check is in flight (UI only; never stored)


@dataclasses.dataclass
class ConnectionCheckResult:
    status: IntegrationStatus
    detail: str                     # sanitised — safe to show in the UI/logs
    checked_at: float = dataclasses.field(default_factory=time.time)
    latency_ms: int | None = None
    model: str | None = None        # the configured model/endpoint id, if any


class IntegrationError(Exception):
    """Raised by an adapter call. ``detail`` is always pre-sanitised."""

    def __init__(self, detail: str, *, status: IntegrationStatus = IntegrationStatus.UNAVAILABLE):
        super().__init__(detail)
        self.detail = detail
        self.status = status


# Credential-shaped substrings to strip from any exception text before it is
# logged or shown — belt-and-suspenders alongside never interpolating a raw
# secret into a message in the first place.
_SECRET_PATTERNS = [
    re.compile(r"Bearer\s+[A-Za-z0-9._\-]{8,}", re.I),
    re.compile(r"(?:nvapi|tvly|apk_user_|apk_|cog_)[A-Za-z0-9._\-]{6,}"),
    re.compile(r"[A-Za-z0-9._\-]{20,}"),  # last resort: any long opaque token-looking run
]


def sanitize(text: str) -> str:
    """Best-effort redaction for text that might echo a credential (provider
    error bodies, URLs with query-string tokens). Never log/display raw
    exception text from an adapter without passing it through this first."""
    out = text
    for pat in _SECRET_PATTERNS:
        out = pat.sub("<redacted>", out)
    return out[:500]


def mask_secret(value: str) -> str:
    """For display only — never the value itself. Shows shape, not content."""
    if not value:
        return ""
    if len(value) <= 8:
        return "••••"
    return f"{value[:4]}…{value[-2:]} ({len(value)} chars)"


class IntegrationAdapter(abc.ABC):
    """One third-party provider. Subclasses implement the two abstract methods;
    everything else (timeout, cancellation, status caching) is shared."""

    #: stable id used in the UI, config keys and the integrations registry
    id: str
    #: human label
    label: str
    #: one-line description of the role this integration plays in Oyster —
    #: shown in the settings panel so a reranker is never confused with a
    #: reasoning/generative model, and Tavily/Devin roles are stated plainly.
    role: str
    default_timeout_s: float = 20.0

    def __init__(self) -> None:
        self._last_check: ConnectionCheckResult | None = None

    @abc.abstractmethod
    def is_configured(self) -> bool:
        """True iff the credentials/base URL needed to even attempt a call are
        present. Must not make a network call."""

    @abc.abstractmethod
    async def _do_check_connection(self) -> ConnectionCheckResult:
        """Make ONE real, cheap request (e.g. list-models, a lightweight GET)
        and return a truthful result. Only called when is_configured() is True.
        Must raise IntegrationError (not a bare exception) on failure, with a
        sanitised detail — or return the result directly."""

    def configured_summary(self) -> dict:
        """Non-secret facts about the current configuration, safe for the UI:
        which model/base-url is set, masked credential shape. Subclasses
        extend via `_extra_summary()`."""
        return {"configured": self.is_configured(), **self._extra_summary()}

    def _extra_summary(self) -> dict:
        return {}

    async def check_connection(self, timeout_s: float | None = None) -> ConnectionCheckResult:
        if not self.is_configured():
            self._last_check = ConnectionCheckResult(
                IntegrationStatus.NOT_CONFIGURED, "No credential configured for this integration.")
            return self._last_check
        t0 = time.perf_counter()
        try:
            result = await asyncio.wait_for(self._do_check_connection(), timeout_s or self.default_timeout_s)
        except asyncio.TimeoutError:
            result = ConnectionCheckResult(
                IntegrationStatus.UNAVAILABLE,
                f"Timed out after {timeout_s or self.default_timeout_s:g}s contacting {self.label}.")
        except IntegrationError as exc:
            result = ConnectionCheckResult(exc.status, exc.detail)
        except Exception as exc:  # never leak a raw exception/url/body to the UI
            result = ConnectionCheckResult(
                IntegrationStatus.UNAVAILABLE, sanitize(f"{type(exc).__name__}: {exc}"))
        result.latency_ms = result.latency_ms or int((time.perf_counter() - t0) * 1000)
        self._last_check = result
        return result

    @property
    def last_check(self) -> ConnectionCheckResult | None:
        return self._last_check

    def status_snapshot(self) -> dict:
        """What the settings panel renders for one integration, without making
        a network call — uses the cached result of the last check() (or
        NOT_CONFIGURED if none has run yet / credentials are absent)."""
        if not self.is_configured():
            status, detail, checked_at = IntegrationStatus.NOT_CONFIGURED, "No credential configured.", None
        elif self._last_check is None:
            status, detail, checked_at = IntegrationStatus.NOT_CONFIGURED, "Not yet tested.", None
        else:
            status, detail, checked_at = self._last_check.status, self._last_check.detail, self._last_check.checked_at
        return {
            "id": self.id, "label": self.label, "role": self.role,
            "status": status.value, "detail": detail, "checked_at": checked_at,
            **self.configured_summary(),
        }
