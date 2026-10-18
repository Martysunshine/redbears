"""The lab's telemetry collector — a small reverse proxy kept separate from
both the target application (Juice Shop) and the test runner (the scenario
executor in services/scenarios/runner.py).

Role separation (brief §4 — "separate the target application, test runner and
telemetry collector"):
  - Juice Shop (the TARGET) binds to 127.0.0.1:<app_port> only and is never
    given to the scenario runner's HTTP client directly.
  - The scenario runner (the TEST RUNNER) is only ever handed
    http://127.0.0.1:<proxy_port> — code-enforced in services/scenarios/runner.py,
    not a convention the model could ignore.
  - This proxy (the TELEMETRY COLLECTOR) is the only thing that talks to the
    target. It forwards every request/response and independently records what
    actually happened (method, path, query, status, timing, byte counts, a
    redacted body preview) to a JSONL file — ground truth for detection
    validation, never the model's account of what it did.

All three run as separate components with a real process/thread boundary
between the collector and the target (the collector is a thread in the Oyster
backend process; the target is Juice Shop's own, separately sandboxed, OS
process) — not a shared database row the model could edit after the fact.

Credentials and session tokens are redacted before anything is written to
disk (brief §8): known-sensitive JSON keys, and the Authorization/Cookie
headers, are replaced with "<redacted>" in the stored record. The live proxy
pass-through to Juice Shop is unredacted (the lab needs the real cookie to
function) — only the telemetry record is sanitised.
"""
from __future__ import annotations

import http.server
import json
import re
import threading
import time
from pathlib import Path
from urllib.parse import urlsplit

import httpx

_SENSITIVE_KEYS = re.compile(r'"(password|token|authorization|cookie|session|otp|secret)"\s*:\s*"(?:[^"\\]|\\.)*"', re.I)
_SENSITIVE_HEADERS = {"authorization", "cookie", "set-cookie"}


def _redact_body(raw: bytes) -> str:
    text = raw[:4000].decode("utf-8", errors="replace")
    return _SENSITIVE_KEYS.sub(lambda m: f'"{m.group(1)}":"<redacted>"', text)


class _Handler(http.server.BaseHTTPRequestHandler):
    server_version = "RedBearsLabProxy/1"

    def log_message(self, *a) -> None:  # silence default stderr logging
        pass

    def _forward(self, method: str) -> None:
        proxy: TelemetryProxy = self.server.proxy  # type: ignore[attr-defined]
        length = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(length) if length else b""
        upstream_url = f"http://127.0.0.1:{proxy.upstream_port}{self.path}"
        fwd_headers = {k: v for k, v in self.headers.items() if k.lower() not in ("host", "content-length")}
        # X-RedBears-Actor is a TEST-HARNESS marker the scenario runner sets on its
        # own requests to label which synthetic identity made them (e.g. "userA"),
        # purely so detection rules written for this lab can be validated without a
        # full JWT-claims/SIEM pipeline. It is never sensitive (no credential, no
        # session value) and is stripped before forwarding so the real application
        # never sees or reacts to it.
        actor = fwd_headers.pop("X-RedBears-Actor", None) or fwd_headers.pop("x-redbears-actor", None)
        t0 = time.monotonic()
        try:
            resp = proxy._client.request(method, upstream_url, headers=fwd_headers, content=body, timeout=15)
        except httpx.HTTPError as exc:
            self.send_response(502)
            self.end_headers()
            proxy._record(method, self.path, body, 502, 0, time.monotonic() - t0, str(exc), actor)
            return
        dur = time.monotonic() - t0
        self.send_response(resp.status_code)
        for k, v in resp.headers.items():
            # content-encoding is dropped too: httpx's `.content` is already
            # decompressed, so re-sending the original "gzip"/"br" header while
            # forwarding plain bytes would make the client double-decode.
            if k.lower() not in ("content-length", "transfer-encoding", "connection", "content-encoding"):
                self.send_header(k, v)
        self.send_header("Content-Length", str(len(resp.content)))
        self.end_headers()
        self.wfile.write(resp.content)
        proxy._record(method, self.path, body, resp.status_code, len(resp.content), dur, None, actor)

    def do_GET(self): self._forward("GET")
    def do_POST(self): self._forward("POST")
    def do_PUT(self): self._forward("PUT")
    def do_PATCH(self): self._forward("PATCH")
    def do_DELETE(self): self._forward("DELETE")
    def do_OPTIONS(self): self._forward("OPTIONS")
    def do_HEAD(self): self._forward("HEAD")


class TelemetryProxy:
    def __init__(self, *, listen_port: int, upstream_port: int, telemetry_path: Path):
        self.upstream_port = upstream_port
        self.telemetry_path = telemetry_path
        self.telemetry_path.parent.mkdir(parents=True, exist_ok=True)
        self._client = httpx.Client()
        self._lock = threading.Lock()
        self._server = http.server.ThreadingHTTPServer(("127.0.0.1", listen_port), _Handler)
        self._server.proxy = self  # type: ignore[attr-defined]
        self._server.daemon_threads = True
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._server.shutdown()
        self._server.server_close()
        self._client.close()

    def _record(self, method: str, path: str, body: bytes, status: int, resp_bytes: int,
               duration_s: float, error: str | None, actor: str | None = None) -> None:
        parts = urlsplit(path)
        record = {
            "ts": time.time(), "method": method, "path": parts.path, "query": parts.query,
            "status": status, "response_bytes": resp_bytes, "duration_ms": round(duration_s * 1000, 1),
            "body_preview": _redact_body(body) if body else None, "error": error, "actor": actor,
        }
        with self._lock, open(self.telemetry_path, "a") as f:
            f.write(json.dumps(record) + "\n")

    def read_events(self) -> list[dict]:
        if not self.telemetry_path.exists():
            return []
        with open(self.telemetry_path) as f:
            return [json.loads(line) for line in f if line.strip()]
