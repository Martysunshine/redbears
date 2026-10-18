"""Read-only evidence check for the IDOR demo lab (no gateway, agent or LLM).

Sends the demo tokens against the two running loopback targets, runs the
acceptance matrix with GET requests only, prints a pass/fail table, and writes
lab/artifacts/last_selfcheck.json. Every expected outcome is explicit, so this
fails loudly if the vulnerable target stops reproducing the flaw or the patched
target starts leaking a record.

    python lab/run_local.py        # in one terminal
    python lab/selfcheck.py        # in another

This is Martin's own verification aid. It performs no writes and only ever talks
to 127.0.0.1. Exit code 0 iff every check matched its expected outcome.
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import httpx

try:  # works as `python -m lab.selfcheck` and as `python lab/selfcheck.py`
    from . import fixtures
except ImportError:  # pragma: no cover - direct-path invocation
    import pathlib
    sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
    from lab import fixtures

VULN_URL = os.environ.get("VULNERABLE_URL", "http://127.0.0.1:18081")
PATCHED_URL = os.environ.get("PATCHED_URL", "http://127.0.0.1:18082")
ARTIFACT = Path(__file__).resolve().parent / "artifacts" / "last_selfcheck.json"

# (name, base_url, persona|None, record_id, expected_status, expected_owner|None)
# expected_owner is asserted only on a 200; None means "no owner expected".
CHECKS = [
    ("vuln  bob->202 own",      "vuln",    "bob",   202, 200, "bob"),
    ("vuln  alice->101 own",    "vuln",    "alice", 101, 200, "alice"),
    ("vuln  bob->101 CROSS",    "vuln",    "bob",   101, 200, "alice"),
    ("vuln  no token",          "vuln",    None,    101, 401, None),
    ("vuln  unknown id",        "vuln",    "alice", 999, 404, None),
    ("patch bob->202 own",      "patched", "bob",   202, 200, "bob"),
    ("patch alice->101 own",    "patched", "alice", 101, 200, "alice"),
    ("patch bob->101 DENIED",   "patched", "bob",   101, 403, None),
    ("patch no token",          "patched", None,    101, 401, None),
    ("patch unknown id",        "patched", "alice", 999, 404, None),
]


def _headers(persona: str | None) -> dict:
    if persona is None:
        return {}
    return {"Authorization": f"Bearer {fixtures.demo_token(persona)}"}


def _run_one(client: httpx.Client, target: str, persona, record_id, exp_status, exp_owner) -> dict:
    base = VULN_URL if target == "vuln" else PATCHED_URL
    result = {"status": None, "owner": None, "leaked": False, "ok": False, "error": None}
    try:
        resp = client.get(f"{base}/api/records/{record_id}", headers=_headers(persona), timeout=5.0)
    except httpx.HTTPError as exc:
        result["error"] = f"{type(exc).__name__}: {exc}"
        return result
    result["status"] = resp.status_code
    status_ok = resp.status_code == exp_status
    owner_ok = True
    if resp.status_code == 200:
        try:
            result["owner"] = resp.json().get("owner")
        except ValueError:
            result["owner"] = None
        if exp_owner is not None:
            owner_ok = result["owner"] == exp_owner
    if resp.status_code != 200:
        # Any non-200 must not carry record content (the patched-leak guard).
        body = resp.text.lower()
        result["leaked"] = ("demo record" in body) or ('"owner"' in body)
    result["ok"] = status_ok and owner_ok and not result["leaked"]
    return result


def main() -> int:
    rows = []
    all_ok = True
    with httpx.Client() as client:
        # Confirm both targets are up and in the expected mode first.
        modes = {}
        for target, base in (("vuln", VULN_URL), ("patched", PATCHED_URL)):
            try:
                h = client.get(f"{base}/health", timeout=5.0).json()
                modes[target] = h.get("mode")
            except httpx.HTTPError as exc:
                print(f"  cannot reach {base}/health: {exc}")
                print("  start the lab first:  python lab/run_local.py")
                return 2
        if modes.get("vuln") != "vulnerable" or modes.get("patched") != "patched":
            print(f"  unexpected modes: {modes} (want vuln=vulnerable, patched=patched)")
            return 2

        for name, target, persona, rid, exp_status, exp_owner in CHECKS:
            r = _run_one(client, target, persona, rid, exp_status, exp_owner)
            all_ok = all_ok and r["ok"]
            rows.append({"check": name, "expected_status": exp_status,
                         "expected_owner": exp_owner, **r})

    width = max(len(r["check"]) for r in rows)
    print(f"\n  Red Bears IDOR lab — self-check ({VULN_URL} / {PATCHED_URL})\n")
    for r in rows:
        mark = "PASS" if r["ok"] else "FAIL"
        got = r["status"] if r["error"] is None else r["error"]
        owner = f" owner={r['owner']}" if r["owner"] else ""
        leak = "  LEAK!" if r["leaked"] else ""
        print(f"  [{mark}] {r['check']:<{width}}  want {r['expected_status']}, got {got}{owner}{leak}")

    ARTIFACT.parent.mkdir(parents=True, exist_ok=True)
    ARTIFACT.write_text(json.dumps(
        {"vulnerable_url": VULN_URL, "patched_url": PATCHED_URL, "all_ok": all_ok, "checks": rows},
        indent=2), encoding="utf-8")
    print(f"\n  {'all checks passed' if all_ok else 'SOME CHECKS FAILED'} — wrote {ARTIFACT}\n")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(main())
