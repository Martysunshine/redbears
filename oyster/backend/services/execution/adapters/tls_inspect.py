"""TLS inspection adapter (Class 2 — low-impact active).

Pure-Python ``ssl``. Performs one TLS handshake against an in-scope host:port
and reports certificate subject/issuer/validity, negotiated protocol + cipher,
and an expiry assessment. No external binary required.
"""

from __future__ import annotations

import socket
import ssl
from datetime import datetime, timezone

from .base import AdapterContext, AdapterResult


async def run(ctx: AdapterContext) -> AdapterResult:
    from ..scope_engine import normalize_target

    p = normalize_target(ctx.target)
    host = p.host
    port = p.port or int(ctx.parameters.get("port", 443))

    try:
        context = ssl.create_default_context()
        # For inspection we want the cert even if validation fails, so retry
        # permissively only to *read* metadata (never to send data).
        try:
            with socket.create_connection((host, port), timeout=min(ctx.timeout_seconds, 10)) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    version = ssock.version()
                    validated = True
        except ssl.SSLCertVerificationError as exc:
            permissive = ssl._create_unverified_context()  # noqa: SLF001 - inspection only
            with socket.create_connection((host, port), timeout=min(ctx.timeout_seconds, 10)) as sock:
                with permissive.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert(binary_form=False) or {}
                    cipher = ssock.cipher()
                    version = ssock.version()
            validated = False
            cert = cert or {"verification_error": str(exc)}
    except socket.timeout:
        return AdapterResult(exit_code=124, error_summary=f"TLS handshake timed out to {host}:{port}")
    except Exception as exc:  # noqa: BLE001
        return AdapterResult(exit_code=1, error_summary=f"TLS inspection failed: {exc}")

    subject = dict(x[0] for x in cert.get("subject", [])) if cert.get("subject") else {}
    issuer = dict(x[0] for x in cert.get("issuer", [])) if cert.get("issuer") else {}
    sans = [v for (k, v) in cert.get("subjectAltName", [])] if cert.get("subjectAltName") else []

    parsed = {
        "host": host,
        "port": port,
        "certificate_validated": validated,
        "tls_version": version,
        "cipher": cipher[0] if cipher else None,
        "subject_cn": subject.get("commonName"),
        "issuer_cn": issuer.get("commonName"),
        "subject_alt_names": sans,
        "not_before": cert.get("notBefore"),
        "not_after": cert.get("notAfter"),
    }
    if cert.get("notAfter"):
        try:
            exp = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
            parsed["expired"] = datetime.now(timezone.utc) > exp
            parsed["days_until_expiry"] = (exp - datetime.now(timezone.utc)).days
        except Exception:
            pass

    lines = [
        f"TLS {host}:{port}",
        f"  Protocol: {version}",
        f"  Cipher:   {cipher[0] if cipher else 'unknown'}",
        f"  Subject:  {subject.get('commonName')}",
        f"  Issuer:   {issuer.get('commonName')}",
        f"  Valid:    {cert.get('notBefore')} -> {cert.get('notAfter')}",
        f"  Chain validated: {validated}",
    ]
    return AdapterResult(stdout="\n".join(lines), exit_code=0, parsed=parsed)


def version() -> str:
    return f"python-ssl ({ssl.OPENSSL_VERSION})"
