"""Who is calling, and what may they do.

Authorization in the gateway depends ONLY on an authenticated Oyster identity —
never on what the client says about itself. A client may report its name
("claude-code", "vscode", "chatgpt") for observability; that string is recorded
in the audit log and used nowhere in an access decision.

Two authenticated identity sources:

* HTTP (Streamable HTTP transport) — a bearer token that is EITHER a verified
  Supabase JWT whose email is allow-listed (the org / individual path) OR one of
  the explicit static tokens configured for local/machine use. Anonymous is
  always refused, even when OYSTER_DISABLE_AUTH is set — the loopback bind and
  stdio are the local conveniences, not an open HTTP port.

* stdio — a local process the operator launched themselves, trusted as the
  configured local operator identity (OYSTER_MCP_LOCAL_EMAIL / _SUB).

The resulting identity is the SAME dict shape the rest of Oyster uses
(``{"tier", "email", "sub"}``) so project isolation via
``services/project_context.py`` applies unchanged.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

import config
from services import auth_service


class AuthError(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _tier_for_email(email: str) -> str:
    email = (email or "").strip().lower()
    if config.DISABLE_AUTH:
        return "admin"
    if email and email in config.ADMIN_EMAILS:
        return "admin"
    return "user"


@dataclass
class Identity:
    """An authenticated caller plus the transport/observability context."""

    oyster: dict                       # {"tier","email","sub"} — the authz identity
    transport: str                     # "stdio" | "http"
    auth_method: str                   # "supabase" | "static_token" | "local"
    token_fingerprint: str = ""        # sha256 prefix of the credential; never the token
    client_name: str = "unknown"       # client-REPORTED; observability only
    client_version: str = "unknown"    # client-REPORTED; observability only
    correlation_id: str = ""
    extra: dict = field(default_factory=dict)

    @property
    def email(self) -> str:
        return (self.oyster.get("email") or "").strip().lower()

    @property
    def sub(self) -> str:
        return self.oyster.get("sub") or ""

    @property
    def tier(self) -> str:
        return self.oyster.get("tier") or "user"

    @property
    def role(self) -> str:
        """Coarse role name used by the tool catalogue's permitted_roles."""
        return "operator" if self.tier == "admin" else "member"

    @property
    def is_operator(self) -> bool:
        return self.tier == "admin"

    def rate_key(self) -> str:
        return f"{self.transport}:{self.auth_method}:{self.token_fingerprint or self.sub}"

    def audit_actor(self) -> str:
        return self.email or self.sub or "unknown"


def _fingerprint(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()[:12]


def resolve_http_identity(authorization_header: str | None) -> Identity:
    """Resolve an HTTP caller from its Authorization header, or raise AuthError.

    Order: configured static token first (cheap, local), then Supabase JWT."""
    if not authorization_header:
        raise AuthError("unauthenticated", "Missing bearer token")
    parts = authorization_header.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer" or not parts[1].strip():
        raise AuthError("unauthenticated", "Malformed Authorization header")
    token = parts[1].strip()

    # 1) Static token map (token -> email it authenticates as).
    who = config.MCP_HTTP_STATIC_TOKENS.get(token)
    if who is not None:
        tier = _tier_for_email(who)
        # A static token still must map to an allow-listed email whenever real
        # auth is on (DISABLE_AUTH=False) — deliberately NOT further gated on
        # ENVIRONMENT: allow-list enforcement must not depend on an operator
        # also remembering to label the deployment "production". (2026-09-14:
        # this used to additionally require ENVIRONMENT=="production", which
        # meant a real, network-reachable deployment left at the ENVIRONMENT
        # default of "development" — an easy, silent operator mistake — got no
        # enforcement here at all, unlike the Supabase-JWT path below, which
        # never had that extra condition. Aligned to match it.)
        if not config.DISABLE_AUTH and who not in config.ADMIN_EMAILS:
            raise AuthError("forbidden", "Token identity is not authorized")
        return Identity(
            oyster={"tier": tier, "email": who, "sub": f"mcp-token-{_fingerprint(token)}"},
            transport="http", auth_method="static_token",
            token_fingerprint=_fingerprint(token),
        )

    # 2) Supabase JWT.
    try:
        claims = auth_service._verify_supabase_token(token)
    except auth_service.AuthServiceUnavailable:
        raise AuthError("unavailable", "Auth service temporarily unavailable")
    if not claims:
        raise AuthError("unauthenticated", "Invalid or expired token")
    email = (claims.get("email") or "").strip().lower()
    sub = claims.get("sub")
    if not sub:
        raise AuthError("unauthenticated", "Token has no subject")
    # A verified but non-allow-listed identity is refused on the HTTP surface —
    # the gateway is an operator tool, not a public API. (DISABLE_AUTH does not
    # widen this: it only affects the local-dev bypass elsewhere.)
    if not config.DISABLE_AUTH and email not in config.ADMIN_EMAILS:
        raise AuthError("forbidden", "Identity is not authorized for the MCP gateway")
    return Identity(
        oyster={"tier": _tier_for_email(email), "email": email, "sub": sub},
        transport="http", auth_method="supabase",
        token_fingerprint=_fingerprint(token),
    )


def resolve_stdio_identity() -> Identity:
    """The local operator identity for the stdio transport."""
    email = config.MCP_LOCAL_EMAIL
    return Identity(
        oyster={"tier": _tier_for_email(email), "email": email, "sub": config.MCP_LOCAL_SUB},
        transport="stdio", auth_method="local",
        token_fingerprint="local",
    )
