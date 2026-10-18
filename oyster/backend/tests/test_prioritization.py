"""Deterministic patch-prioritization engine: missing data must never
silently become zero risk, factors must be explainable, and the score must
be a pure function of installed data (no LLM, no randomness)."""

from __future__ import annotations

from services.knowledge.vulnerabilities import prioritization


def _rec(**overrides) -> dict:
    base = {
        "cve_id": "CVE-2026-00001",
        "kev": {"listed": False},
        "epss": None,
        "cvss": {"v3": None, "v4": None, "v2": None, "preferred_source": None},
        "cvss_source": None,
        "vendor_advisories": [],
        "citation": {"source_url": "https://nvd.nist.gov/vuln/detail/CVE-2026-00001"},
    }
    base.update(overrides)
    return base


def test_unknown_cve_reports_not_found():
    r = prioritization.score_cve("CVE-9999-99999")
    # not seeded anywhere in the test DB -> not found
    assert r["found"] is False


def test_missing_epss_and_cvss_are_excluded_not_zeroed(monkeypatch):
    """A CVE where only KEV=True is known must score based on KEV alone
    (fully renormalized), never as if EPSS/CVSS were 0."""
    monkeypatch.setattr(prioritization.retrieval, "get_cve",
                        lambda cid: _rec(kev={"listed": True, "date_added": "2026-01-01"}))
    r = prioritization.score_cve("CVE-2026-00001")
    assert r["found"] is True
    assert r["score"] == 1.0  # KEV is the only present factor and it's 1.0 -> renormalized to 1.0
    assert "epss" in r["missing_factors"]
    assert "cvss" in r["missing_factors"]
    assert r["factors"]["epss"]["value"] is None
    assert r["factors"]["cvss"]["value"] is None


def test_confidence_reflects_core_data_completeness(monkeypatch):
    monkeypatch.setattr(prioritization.retrieval, "get_cve", lambda cid: _rec())
    r = prioritization.score_cve("CVE-2026-00001")
    # kev present (False is real data), epss+cvss missing -> 1/3 core factors present
    assert abs(r["confidence"] - round(1 / 3, 2)) < 1e-9

    monkeypatch.setattr(
        prioritization.retrieval, "get_cve",
        lambda cid: _rec(epss={"score": 0.5, "percentile": 0.9},
                         cvss={"v3": {"score": 9.0, "severity": "CRITICAL"}, "v4": None, "v2": None,
                              "preferred_source": "nvd"}))
    r2 = prioritization.score_cve("CVE-2026-00001")
    assert r2["confidence"] == 1.0
    assert not ({"kev", "epss", "cvss"} & set(r2["missing_factors"]))


def test_kev_false_is_real_data_not_missing(monkeypatch):
    monkeypatch.setattr(prioritization.retrieval, "get_cve", lambda cid: _rec(kev={"listed": False}))
    r = prioritization.score_cve("CVE-2026-00001")
    assert "kev" not in r["missing_factors"]
    assert r["factors"]["kev"]["value"] == 0.0


def test_higher_epss_and_cvss_score_higher(monkeypatch):
    def low(cid):
        return _rec(epss={"score": 0.01}, cvss={"v3": {"score": 2.0, "severity": "LOW"},
                    "v4": None, "v2": None, "preferred_source": "nvd"})

    def high(cid):
        return _rec(epss={"score": 0.95}, cvss={"v3": {"score": 9.8, "severity": "CRITICAL"},
                    "v4": None, "v2": None, "preferred_source": "nvd"})

    monkeypatch.setattr(prioritization.retrieval, "get_cve", low)
    lo = prioritization.score_cve("CVE-2026-00001")
    monkeypatch.setattr(prioritization.retrieval, "get_cve", high)
    hi = prioritization.score_cve("CVE-2026-00001")
    assert hi["score"] > lo["score"]
    assert hi["band"] in ("critical", "high")
    assert lo["band"] in ("low", "medium")


def test_fix_available_vs_no_fix_vs_unknown(monkeypatch):
    monkeypatch.setattr(prioritization.retrieval, "get_cve",
                        lambda cid: _rec(vendor_advisories=[{"fixed_version": "1.2.3",
                                                              "current_release_date": None}]))
    r_fixed = prioritization.score_cve("CVE-2026-00001")
    assert r_fixed["factors"]["fix_available"]["value"] == 1.0
    assert "fix_available" not in r_fixed["missing_factors"]

    monkeypatch.setattr(prioritization.retrieval, "get_cve",
                        lambda cid: _rec(vendor_advisories=[{"fixed_version": None,
                                                              "current_release_date": None}]))
    r_nofix = prioritization.score_cve("CVE-2026-00001")
    assert r_nofix["factors"]["fix_available"]["value"] == 0.0

    monkeypatch.setattr(prioritization.retrieval, "get_cve", lambda cid: _rec(vendor_advisories=[]))
    r_unknown = prioritization.score_cve("CVE-2026-00001")
    assert r_unknown["factors"]["fix_available"]["value"] is None
    assert "fix_available" in r_unknown["missing_factors"]


def test_asset_context_optional_and_never_defaults_to_zero(monkeypatch):
    monkeypatch.setattr(prioritization.retrieval, "get_cve",
                        lambda cid: _rec(kev={"listed": True, "date_added": "2026-01-01"}))
    no_context = prioritization.score_cve("CVE-2026-00001")
    assert "asset_criticality" in no_context["missing_factors"]
    assert "asset_exposure" in no_context["missing_factors"]

    with_context = prioritization.score_cve("CVE-2026-00001", asset_criticality=1.0, asset_exposure=1.0)
    assert "asset_criticality" not in with_context["missing_factors"]
    assert with_context["score"] == 1.0  # kev=1, criticality=1, exposure=1 all present and maxed


def test_explanation_and_note_are_present_and_non_universal_disclaimer(monkeypatch):
    monkeypatch.setattr(prioritization.retrieval, "get_cve",
                        lambda cid: _rec(kev={"listed": True, "date_added": "2026-01-01"}))
    r = prioritization.score_cve("CVE-2026-00001")
    assert any("KEV" in e for e in r["explanation"])
    assert "not a universal risk score" in r["note"]


def test_rank_cves_sorts_highest_first(monkeypatch):
    recs = {
        "CVE-2026-LOW": _rec(cve_id="CVE-2026-LOW", epss={"score": 0.01}),
        "CVE-2026-HIGH": _rec(cve_id="CVE-2026-HIGH", kev={"listed": True, "date_added": "2026-01-01"},
                              epss={"score": 0.9}),
    }
    monkeypatch.setattr(prioritization.retrieval, "get_cve", lambda cid: recs[cid])
    ranked = prioritization.rank_cves(["CVE-2026-LOW", "CVE-2026-HIGH"])
    assert ranked[0]["cve_id"] == "CVE-2026-HIGH"
    assert ranked[1]["cve_id"] == "CVE-2026-LOW"
