"""Regression test for the token-leak this store's redaction originally had:
matching sensitive KEY NAMES exactly ("token") missed any compound key like
"bid_token" or "access_token", letting real session tokens reach disk."""
from services.investigation import store


def test_redacts_keys_containing_sensitive_substrings():
    raw = {
        "bid_token": {"6": "eyJhbGciOiJIUzI1NiJ9.real-looking-jwt.sig", "7": "another-token-value"},
        "access_token": "abc123",
        "nested": {"user_password": "p@ss", "ok_field": "keep-me"},
        "plain": "keep-me-too",
    }
    out = store._redact(raw)
    assert out["bid_token"] == "<redacted>"
    assert out["access_token"] == "<redacted>"
    assert out["nested"]["user_password"] == "<redacted>"
    assert out["nested"]["ok_field"] == "keep-me"
    assert out["plain"] == "keep-me-too"


def test_create_and_round_trip_investigation(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "_PATH", tmp_path / "investigations.json")
    inv_id = store.create_investigation({"scenario_id": "sqli_login_bypass", "secret_token": "shh"})
    got = store.get_investigation(inv_id)
    assert got["scenario_id"] == "sqli_login_bypass"
    assert got["secret_token"] == "<redacted>"
    assert inv_id in [r["id"] for r in store.list_investigations()]
