"""MITRE CAPEC XML parser — offline, small synthetic catalog (real schema shape)."""

from __future__ import annotations

import pytest

from services.knowledge.vulnerabilities.sources import capec

_XML = """<?xml version="1.0" encoding="UTF-8"?>
<Attack_Pattern_Catalog Name="CAPEC" Version="3.9" Date="2023-01-24"
    xmlns="http://capec.mitre.org/capec-3"
    xmlns:xhtml="http://www.w3.org/1999/xhtml">
  <Attack_Patterns>
    <Attack_Pattern ID="66" Name="SQL Injection" Abstraction="Standard" Status="Draft">
      <Description>This attack exploits target software that constructs SQL statements.</Description>
      <Likelihood_Of_Attack>High</Likelihood_Of_Attack>
      <Typical_Severity>High</Typical_Severity>
      <Related_Attack_Patterns>
        <Related_Attack_Pattern Nature="ChildOf" CAPEC_ID="248"/>
      </Related_Attack_Patterns>
      <Execution_Flow>
        <Attack_Step><Step>1</Step><Phase>Explore</Phase><Description>Survey the app.</Description></Attack_Step>
      </Execution_Flow>
      <Prerequisites>
        <Prerequisite>The application does not validate input.</Prerequisite>
      </Prerequisites>
      <Skills_Required>
        <Skill Level="High">Familiarity with SQL.</Skill>
      </Skills_Required>
      <Related_Weaknesses>
        <Related_Weakness CWE_ID="89"/>
      </Related_Weaknesses>
      <Mitigations>
        <Mitigation>Use parameterized queries.</Mitigation>
      </Mitigations>
      <References>
        <Reference External_Reference_ID="REF-1"/>
      </References>
    </Attack_Pattern>
  </Attack_Patterns>
  <External_References>
    <External_Reference Reference_ID="REF-1">
      <Title>OWASP SQL Injection</Title>
      <URL>https://owasp.org/sqli</URL>
    </External_Reference>
  </External_References>
</Attack_Pattern_Catalog>
"""


def test_normalize_extracts_attack_pattern_with_all_sections():
    records, version, findings = capec.normalize(_XML.encode("utf-8"))
    assert version == "3.9"
    rec = next(r for r in records if r.capec_id == "CAPEC-66")
    assert rec.name == "SQL Injection"
    assert rec.likelihood_of_attack == "High"
    assert rec.typical_severity == "High"
    assert rec.related_weaknesses == ["CWE-89"]
    assert rec.related_attack_patterns == [{"nature": "ChildOf", "capec_id": "CAPEC-248"}]
    assert rec.prerequisites == ["The application does not validate input."]
    assert rec.skills_required[0]["level"] == "High"
    assert rec.mitigations[0]["description"] == "Use parameterized queries."
    assert len(rec.execution_flow) == 1
    assert rec.execution_flow[0]["phase"] == "Explore"


def test_normalize_resolves_reference_urls():
    records, _, _ = capec.normalize(_XML.encode("utf-8"))
    rec = records[0]
    assert rec.references[0]["url"] == "https://owasp.org/sqli"


def test_normalize_malformed_xml_raises_rather_than_silently_returning_garbage():
    with pytest.raises(Exception):
        capec.normalize(b"<not><valid")
