"""Pack metadata validation + checksum + migration tests (no embedding needed)."""

from __future__ import annotations

from services.knowledge import registry, store


def test_all_ondisk_packs_valid():
    packs = registry.list_packs()
    assert len(packs) >= 5
    invalid = [p["id"] for p in packs if not p.get("valid")]
    assert invalid == [], f"invalid packs: {invalid}"


def test_primary_packs_present_with_full_metadata():
    by_id = {p["id"]: p for p in registry.list_packs()}
    for pid in ("kali-linux", "owasp-wstg", "hacktricks", "gtfobins", "mitre-attack"):
        assert pid in by_id, f"missing primary pack {pid}"
        p = by_id[pid]
        # full machine-readable metadata schema
        for key in ("version", "licence", "attribution", "trust_level",
                    "risk_classification", "source_urls", "content_checksum",
                    "freshness_policy", "security_domain"):
            assert p.get(key) not in (None, ""), f"{pid} missing {key}"
        assert p["source_urls"], f"{pid} has no source urls"


def test_required_fields_enforced(tmp_path, monkeypatch):
    import config
    bad = tmp_path / "packs" / "broken"
    bad.mkdir(parents=True)
    (bad / "pack.json").write_text('{"id": "broken"}')  # missing version+title
    monkeypatch.setattr(config, "KNOWLEDGE_PACKS_DIR", tmp_path / "packs")
    p = registry.get_pack("broken")
    assert p is not None and p["valid"] is False


def test_checksum_changes_with_content(tmp_path, monkeypatch):
    import config
    d = tmp_path / "packs" / "p1"
    d.mkdir(parents=True)
    (d / "doc.md").write_text("original content")
    (d / "pack.json").write_text(
        '{"id":"p1","version":"1.0.0","title":"P1","docs":[{"file":"doc.md"}]}')
    monkeypatch.setattr(config, "KNOWLEDGE_PACKS_DIR", tmp_path / "packs")
    c1 = registry.get_pack("p1")["content_checksum"]
    (d / "doc.md").write_text("changed content")
    c2 = registry.get_pack("p1")["content_checksum"]
    assert c1 != c2


def test_official_trust_inferred():
    by_id = {p["id"]: p for p in registry.list_packs()}
    assert by_id["mitre-attack"]["trust_level"] == "official"
    assert by_id["hacktricks"]["trust_level"] == "community"


def test_migrations_add_columns():
    cols = {r[1] for r in store.conn().execute("PRAGMA table_info(knowledge_packs)")}
    for c in ("enabled", "content_checksum", "licence", "risk_classification",
              "trust_level", "update_status", "installation_status"):
        assert c in cols, f"migration missing column {c}"


def test_chunk_and_updates_tables_exist():
    names = {r[0] for r in store.conn().execute(
        "SELECT name FROM sqlite_master WHERE type='table'")}
    assert "knowledge_chunks" in names
    assert "knowledge_pack_updates" in names
