"""Install / enable-disable / update-checksum / history tests.

Uses the ``fake_embedding`` fixture so no embedding model or Chroma is loaded —
the SQLite provenance side (which powers lexical search + citations) is real.
"""

from __future__ import annotations

import pytest

from services.knowledge import pack_service, store


async def test_install_writes_provenance_and_state(fake_embedding):
    res = await pack_service.install("gtfobins")
    assert res["ok"] is True
    assert res["chunks"] > 0
    assert pack_service.is_installed("gtfobins")
    # provenance rows exist and carry source metadata
    rows = store.conn().execute(
        "SELECT * FROM knowledge_chunks WHERE pack_id='gtfobins'").fetchall()
    assert len(rows) == res["chunks"]
    r0 = dict(rows[0])
    assert r0["canonical_url"] and r0["content_hash"] and r0["source_type"] == "built_in"


async def test_enable_disable_gates_retrieval(fake_embedding):
    await pack_service.install("kali-linux")
    assert pack_service.is_enabled("kali-linux")
    assert "kali-linux" in store.enabled_pack_ids()
    pack_service.set_enabled("kali-linux", False)
    assert "kali-linux" not in store.enabled_pack_ids()
    # disabled pack yields no hybrid results
    hits = await pack_service.search("kali metapackages apt", top_k=5)
    assert hits == []
    pack_service.set_enabled("kali-linux", True)
    assert "kali-linux" in store.enabled_pack_ids()


async def test_uninstall_removes_everything(fake_embedding):
    await pack_service.install("mitre-attack")
    await pack_service.uninstall("mitre-attack")
    assert not pack_service.is_installed("mitre-attack")
    rows = store.conn().execute(
        "SELECT COUNT(*) c FROM knowledge_chunks WHERE pack_id='mitre-attack'").fetchone()
    assert rows["c"] == 0


async def test_update_checksum_comparison(fake_embedding, monkeypatch):
    await pack_service.install("owasp-wstg")
    chk = pack_service.check_update("owasp-wstg")
    assert chk["status"] == "current"
    # simulate upstream drift: patch registry to report a new checksum/version
    from services.knowledge import registry
    real = registry.get_pack("owasp-wstg")
    drifted = {**real, "version": "1.1.0", "content_checksum": "deadbeef" * 8}
    monkeypatch.setattr(registry, "get_pack", lambda pid: drifted if pid == "owasp-wstg" else real)
    chk2 = pack_service.check_update("owasp-wstg")
    assert chk2["status"] == "update-available"
    assert chk2["available_version"] == "1.1.0"


async def test_history_records_install(fake_embedding):
    await pack_service.install("gtfobins")
    hist = pack_service.history("gtfobins")
    assert any(h["action"] == "install" for h in hist)


async def test_reinstall_is_idempotent(fake_embedding):
    a = await pack_service.install("kali-linux")
    b = await pack_service.install("kali-linux")
    assert a["chunks"] == b["chunks"]
    rows = store.conn().execute(
        "SELECT COUNT(*) c FROM knowledge_chunks WHERE pack_id='kali-linux'").fetchone()
    assert rows["c"] == b["chunks"]  # no duplication
