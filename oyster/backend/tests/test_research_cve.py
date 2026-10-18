"""research_cve() — Security Intel's "Research this CVE" handoff. Verifies the
brief's own constraint structurally: a CVE never gets lab validation just
because it shares a vulnerability class with an implemented scenario — only
an explicit CVE_SCENARIO_COMPAT entry for that exact id can enable it. No
Tavily/Nemotron credential exists on this machine, so research/investigate
report "skipped" here, exactly as they would live.
"""
from __future__ import annotations

import pytest

from services.investigation import store, workflow


@pytest.fixture(autouse=True)
def _isolated_store(tmp_path, monkeypatch):
    monkeypatch.setattr(store, "_PATH", tmp_path / "investigations.json")


@pytest.mark.asyncio
async def test_research_cve_with_no_compatible_scenario_is_research_only():
    result = await workflow.research_cve("CVE-2024-12345", summary="A SQL injection example.")
    assert result["lab_validation"] == "skipped"
    assert result["scenario_id"] is None
    assert result["simulation"] == "not_attempted"
    assert "research only" in result["lab_validation_detail"].lower()
    stages = {s["stage"]: s for s in result["stages"]}
    assert stages["research"]["stage"] == "research"
    assert stages["investigate"]["detail"] == "Research only — no compatible lab test for this CVE."


@pytest.mark.asyncio
async def test_research_cve_persists_an_investigation_record():
    result = await workflow.research_cve("CVE-2024-99999")
    rec = store.get_investigation(result["investigation_id"])
    assert rec is not None
    assert rec["seed_cve_id"] == "CVE-2024-99999"


@pytest.mark.asyncio
async def test_matching_vulnerability_class_alone_never_enables_lab_validation(monkeypatch):
    """Even if a CVE's summary mentions SQL injection — the same class as the
    implemented sqli_login scenario — it must not run that scenario unless
    CVE_SCENARIO_COMPAT names this exact CVE id."""
    assert "CVE-2099-00001" not in workflow.CVE_SCENARIO_COMPAT
    result = await workflow.research_cve(
        "CVE-2099-00001", summary="A classic SQL injection in a login form, just like Juice Shop's.")
    assert result["lab_validation"] == "skipped"
    assert result["lab_instance_id"] is None
