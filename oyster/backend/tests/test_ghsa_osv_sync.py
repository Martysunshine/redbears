"""GHSA/OSV sync orchestration — offline, mocking the fetch layer (clone /
zip download) so no live network or git is touched."""

from __future__ import annotations

from pathlib import Path

import pytest

from services.knowledge.vulnerabilities import osv_store as store
from services.knowledge.vulnerabilities import sync as vsync
from services.knowledge.vulnerabilities.sources import ghsa as ghsa_src
from services.knowledge.vulnerabilities.sources import osv as osv_src


def _advisory(ghsa_id, cve=None, summary="s", withdrawn=None):
    d = {"id": ghsa_id, "summary": summary, "aliases": [cve] if cve else [],
        "affected": [], "references": [], "database_specific": {"cwe_ids": []}}
    if withdrawn:
        d["withdrawn"] = withdrawn
    return d


# ---------------------------------------------------------------------------
# GHSA
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_sync_ghsa_processes_all_files_and_cleans_up(monkeypatch):
    advisories = {
        "GHSA-2345-6789-CFGH": _advisory("GHSA-2345-6789-CFGH", cve="CVE-2024-70001"),
        "GHSA-2345-6789-CFGJ": _advisory("GHSA-2345-6789-CFGJ", cve="CVE-2024-70002"),
    }
    fake_files = [Path(f"/fake/{k}.json") for k in advisories]
    cleanup_calls = []

    monkeypatch.setattr(ghsa_src, "clone_reviewed_advisories", lambda: (Path("/fake"), "abc123sha"))
    monkeypatch.setattr(ghsa_src, "iter_advisory_files", lambda d: iter(fake_files))
    monkeypatch.setattr(ghsa_src, "load_advisory", lambda p: advisories[p.stem])
    monkeypatch.setattr(ghsa_src, "cleanup", lambda d: cleanup_calls.append(d))

    r = await vsync.sync_ghsa()
    assert r["ok"] is True
    assert r["added"] == 2
    assert r["commit"] == "abc123sha"
    assert cleanup_calls == [Path("/fake")]
    assert store.get_ghsa("GHSA-2345-6789-CFGH") is not None


@pytest.mark.asyncio
async def test_sync_ghsa_isolates_malformed_file_and_still_cleans_up(monkeypatch):
    fake_files = [Path("/fake/GHSA-2345-6789-CFGH.json"), Path("/fake/GHSA-BAD.json")]
    cleanup_calls = []

    def fake_load(p):
        if "BAD" in p.name:
            return None  # unreadable/malformed
        return _advisory("GHSA-2345-6789-CFGH")

    monkeypatch.setattr(ghsa_src, "clone_reviewed_advisories", lambda: (Path("/fake"), "sha1"))
    monkeypatch.setattr(ghsa_src, "iter_advisory_files", lambda d: iter(fake_files))
    monkeypatch.setattr(ghsa_src, "load_advisory", fake_load)
    monkeypatch.setattr(ghsa_src, "cleanup", lambda d: cleanup_calls.append(d))

    r = await vsync.sync_ghsa()
    assert r["ok"] is True
    assert r["added"] == 1
    assert r["failed"] == 1
    assert cleanup_calls == [Path("/fake")]  # cleanup still runs despite the failure


@pytest.mark.asyncio
async def test_sync_ghsa_cleans_up_even_when_a_later_step_raises(monkeypatch):
    cleanup_calls = []

    def boom(p):
        raise RuntimeError("disk read error")

    monkeypatch.setattr(ghsa_src, "clone_reviewed_advisories", lambda: (Path("/fake"), "sha2"))
    monkeypatch.setattr(ghsa_src, "iter_advisory_files", lambda d: iter([Path("/fake/GHSA-x.json")]))
    monkeypatch.setattr(ghsa_src, "load_advisory", boom)
    monkeypatch.setattr(ghsa_src, "cleanup", lambda d: cleanup_calls.append(d))

    with pytest.raises(RuntimeError):
        await vsync.sync_ghsa()
    assert cleanup_calls == [Path("/fake")]


@pytest.mark.asyncio
async def test_sync_ghsa_tracks_withdrawn_advisories(monkeypatch):
    advisories = {"GHSA-2345-6789-CFGH": _advisory("GHSA-2345-6789-CFGH", withdrawn="2026-01-01T00:00:00Z")}
    monkeypatch.setattr(ghsa_src, "clone_reviewed_advisories", lambda: (Path("/fake"), "sha3"))
    monkeypatch.setattr(ghsa_src, "iter_advisory_files",
                        lambda d: iter([Path(f"/fake/{k}.json") for k in advisories]))
    monkeypatch.setattr(ghsa_src, "load_advisory", lambda p: advisories[p.stem])
    monkeypatch.setattr(ghsa_src, "cleanup", lambda d: None)

    r = await vsync.sync_ghsa()
    assert r["withdrawn"] == 1
    assert store.get_ghsa("GHSA-2345-6789-CFGH")["is_withdrawn"] is True


@pytest.mark.asyncio
async def test_sync_ghsa_second_run_is_idempotent(monkeypatch):
    advisories = {"GHSA-2345-6789-CFGH": _advisory("GHSA-2345-6789-CFGH")}
    monkeypatch.setattr(ghsa_src, "clone_reviewed_advisories", lambda: (Path("/fake"), "sha4"))
    monkeypatch.setattr(ghsa_src, "iter_advisory_files",
                        lambda d: iter([Path(f"/fake/{k}.json") for k in advisories]))
    monkeypatch.setattr(ghsa_src, "load_advisory", lambda p: advisories[p.stem])
    monkeypatch.setattr(ghsa_src, "cleanup", lambda d: None)

    r1 = await vsync.sync_ghsa()
    assert r1["added"] == 1
    r2 = await vsync.sync_ghsa()
    assert r2["unchanged"] == 1
    assert r2["added"] == 0


# ---------------------------------------------------------------------------
# OSV
# ---------------------------------------------------------------------------

@pytest.mark.asyncio
async def test_sync_osv_ecosystem_skips_ghsa_shaped_duplicate_ids(monkeypatch):
    records = [
        {"id": "PYSEC-2024-1", "summary": "real osv-native record", "aliases": [], "affected": []},
        {"id": "GHSA-2345-6789-CFGH", "summary": "mirrored from GHSA", "aliases": [], "affected": []},
    ]

    async def fake_download(ecosystem, dest_dir, **kw):
        return Path("/fake/PyPI.zip")

    monkeypatch.setattr(osv_src, "download_ecosystem_zip", fake_download)
    monkeypatch.setattr(osv_src, "iter_records_from_zip", lambda p: iter(records))
    monkeypatch.setattr(osv_src, "cleanup", lambda p: None)

    r = await vsync.sync_osv_ecosystem("PyPI")
    assert r["ok"] is True
    assert r["added"] == 1
    assert r["skipped_ghsa_duplicate"] == 1
    assert store.get_osv("PYSEC-2024-1") is not None
    assert store.get_osv("GHSA-2345-6789-CFGH") is None  # never stored under osv_*


@pytest.mark.asyncio
async def test_sync_osv_ecosystem_tags_records_with_their_source_ecosystem(monkeypatch):
    records = [{"id": "GO-2024-9999", "summary": "s", "aliases": [], "affected": []}]

    async def fake_download(ecosystem, dest_dir, **kw):
        return Path("/fake/Go.zip")

    monkeypatch.setattr(osv_src, "download_ecosystem_zip", fake_download)
    monkeypatch.setattr(osv_src, "iter_records_from_zip", lambda p: iter(records))
    monkeypatch.setattr(osv_src, "cleanup", lambda p: None)

    r = await vsync.sync_osv_ecosystem("Go")
    assert r["ok"] is True
    got = store.get_osv("GO-2024-9999")
    assert got["ecosystem_source"] == "Go"


@pytest.mark.asyncio
async def test_sync_osv_ecosystem_isolates_malformed_record(monkeypatch):
    records = [{"id": "GO-2024-1111", "summary": "s", "aliases": [], "affected": []},
              "not-even-a-dict"]

    async def fake_download(ecosystem, dest_dir, **kw):
        return Path("/fake/Go.zip")

    monkeypatch.setattr(osv_src, "download_ecosystem_zip", fake_download)
    monkeypatch.setattr(osv_src, "iter_records_from_zip", lambda p: iter(records))
    monkeypatch.setattr(osv_src, "cleanup", lambda p: None)

    r = await vsync.sync_osv_ecosystem("Go")
    assert r["ok"] is True
    assert r["added"] == 1
    assert r["failed"] == 1


@pytest.mark.asyncio
async def test_sync_osv_download_failure_isolated_never_raises(monkeypatch):
    async def fake_download(ecosystem, dest_dir, **kw):
        raise TimeoutError("network unreachable")

    monkeypatch.setattr(osv_src, "download_ecosystem_zip", fake_download)

    r = await vsync.sync_osv_ecosystem("npm")
    assert r["ok"] is False
    assert "error" in r


@pytest.mark.asyncio
async def test_sync_osv_all_runs_every_configured_ecosystem_and_isolates_one_failure(monkeypatch):
    async def fake_download(ecosystem, dest_dir, **kw):
        if ecosystem == "Go":
            raise TimeoutError("simulated network failure for Go")
        return Path(f"/fake/{ecosystem}.zip")

    monkeypatch.setattr(osv_src, "download_ecosystem_zip", fake_download)
    monkeypatch.setattr(osv_src, "iter_records_from_zip", lambda p: iter([]))
    monkeypatch.setattr(osv_src, "cleanup", lambda p: None)
    monkeypatch.setattr(osv_src, "ECOSYSTEMS", ["npm", "Go", "NuGet"])

    r = await vsync.sync_osv_all()
    assert r["ok"] is False  # one ecosystem failed
    assert r["by_ecosystem"]["npm"]["ok"] is True
    assert r["by_ecosystem"]["Go"]["ok"] is False
    assert r["by_ecosystem"]["NuGet"]["ok"] is True  # Go's failure didn't stop the others
