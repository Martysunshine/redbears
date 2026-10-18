"""NIST OSCAL control-catalog parsing + structured store + router/answer
integration — offline, synthetic fixtures, no network."""

from __future__ import annotations

from services.knowledge import security_answer, security_router
from services.knowledge.controls import oscal, store
from services.knowledge.graph import builder as graph_builder


# ---------------------------------------------------------------------------
# oscal.py — pure parsing functions
# ---------------------------------------------------------------------------

def test_statement_text_resolves_params_and_bullets():
    parts = [{
        "name": "statement",
        "parts": [
            {"name": "item", "prose": "Do {{ insert: param, p1 }}."},
            {"name": "item", "prose": "Also do this.",
             "parts": [{"name": "item", "prose": "Nested sub-step."}]},
        ],
    }]
    params = [{"id": "p1", "label": "the thing"}]
    text = oscal.statement_text(parts, params)
    assert "Do [the thing]." in text
    assert "Also do this." in text
    assert "Nested sub-step." in text


def test_statement_text_falls_back_to_param_id_when_no_label():
    parts = [{"name": "statement", "parts": [
        {"name": "item", "prose": "Insert {{ insert: param, mystery_id }} here."},
    ]}]
    text = oscal.statement_text(parts, [])
    assert "[mystery_id]" in text  # never invented — falls back to the raw id


def test_guidance_and_examples():
    parts = [
        {"name": "guidance", "prose": "Do this carefully."},
        {"name": "example", "prose": "Example one."},
        {"name": "example", "prose": "Example two."},
    ]
    assert oscal.guidance_text(parts, []) == "Do this carefully."
    assert oscal.examples(parts, []) == ["Example one.", "Example two."]


def test_related_links_and_external_reference_links():
    links = [
        {"rel": "related", "href": "#ia-1"},
        {"rel": "external_reference", "href": "#res-1", "text": "ID.GV-3"},
        {"rel": "reference", "href": "#ignored"},
    ]
    related = oscal.related_links(links, "sp800-53")
    assert related == [{"rel": "related", "target_framework": "sp800-53",
                        "target_control_id": "IA-1", "note": None}]
    ext = oscal.external_reference_links(links, {"res-1": "NIST CSF"})
    assert ext == [{"rel": "external_reference", "target_framework": None,
                    "target_control_id": None, "note": "NIST CSF: ID.GV-3"}]


def test_display_id_normalizes_sp80053_enhancements():
    assert oscal.display_id("ac-1", "sp800-53") == "AC-1"
    assert oscal.display_id("ac-2.1", "sp800-53") == "AC-2(1)"
    assert oscal.display_id("GV.OC-01", "csf") == "GV.OC-01"
    assert oscal.display_id("PO.1.1", "ssdf") == "PO.1.1"


def _tiny_catalog():
    return {
        "back-matter": {"resources": []},
        "groups": [{
            "id": "ac", "class": "family", "title": "Access Control",
            "controls": [{
                "id": "ac-1", "class": "SP800-53", "title": "Policy and Procedures",
                "params": [],
                "parts": [
                    {"name": "statement", "prose": "Develop policy."},
                    {"name": "guidance", "prose": "Guidance text."},
                ],
                "links": [{"rel": "related", "href": "#ia-1"}],
                "controls": [{
                    "id": "ac-1.1", "class": "SP800-53-enhancement", "title": "Automated",
                    "params": [], "parts": [{"name": "statement", "prose": "Automate it."}],
                }],
            }],
        }],
    }


def test_walk_catalog_flattens_family_control_enhancement():
    records, links = oscal.walk_catalog(_tiny_catalog(), "sp800-53")
    by_id = {r["control_id"]: r for r in records}
    assert by_id["AC"]["class"] == "family"
    assert by_id["AC-1"]["class"] == "control"
    assert by_id["AC-1"]["parent_id"] == "AC"
    assert by_id["AC-1"]["statement"] == "Develop policy."
    assert by_id["AC-1(1)"]["class"] == "enhancement"
    assert by_id["AC-1(1)"]["parent_id"] == "AC-1"
    assert links["AC-1"][0]["target_control_id"] == "IA-1"


# ---------------------------------------------------------------------------
# controls/store.py — CRUD roundtrip
# ---------------------------------------------------------------------------

def test_upsert_and_get_control_roundtrip():
    rec = {"framework": "csf", "control_id": "GV.OC-01", "parent_id": "GV.OC",
          "class": "subcategory", "title": "GV.OC-01",
          "statement": "The organizational mission is understood.",
          "guidance": None, "examples_json": '["Example text."]',
          "external_refs_json": None, "source_url": "https://doi.org/x",
          "source_title": "NIST CSF 2.0", "publisher": "NIST", "version": "1.2.0",
          "published_date": "2026-01-01"}
    changed = store.upsert_control(rec)
    assert changed is True

    fetched = store.get_control("csf", "gv.oc-01")  # case-insensitive lookup
    assert fetched["title"] == "GV.OC-01"
    assert fetched["examples"] == ["Example text."]

    # idempotent re-sync of unchanged data writes nothing
    assert store.upsert_control(rec) is False


def test_find_control_any_framework():
    store.upsert_control({"framework": "ssdf", "control_id": "PO.1.1", "parent_id": "PO.1",
                          "class": "task", "title": "PO.1.1", "statement": "Identify requirements.",
                          "guidance": None, "examples_json": None, "external_refs_json": None,
                          "source_url": None, "source_title": None, "publisher": None,
                          "version": None, "published_date": None})
    found = store.find_control_any_framework("PO.1.1")
    assert found is not None
    assert found["framework"] == "ssdf"
    assert store.find_control_any_framework("NO-SUCH-ID") is None


def test_replace_links_and_get_children():
    store.upsert_control({"framework": "sp800-53", "control_id": "AC", "parent_id": None,
                          "class": "family", "title": "Access Control", "statement": None,
                          "guidance": None, "examples_json": None, "external_refs_json": None,
                          "source_url": None, "source_title": None, "publisher": None,
                          "version": None, "published_date": None})
    store.upsert_control({"framework": "sp800-53", "control_id": "AC-1", "parent_id": "AC",
                          "class": "control", "title": "Policy", "statement": "Do it.",
                          "guidance": None, "examples_json": None, "external_refs_json": None,
                          "source_url": None, "source_title": None, "publisher": None,
                          "version": None, "published_date": None})
    store.replace_links("sp800-53", "AC-1", [
        {"rel": "related", "target_framework": "sp800-53", "target_control_id": "IA-1", "note": None},
    ])
    links = store.get_links("sp800-53", "AC-1")
    assert links == [{"rel": "related", "target_framework": "sp800-53",
                      "target_control_id": "IA-1", "note": None}]
    children = store.get_children("sp800-53", "AC")
    assert [c["control_id"] for c in children] == ["AC-1"]


# ---------------------------------------------------------------------------
# security_router.py — NIST control identifier extraction + routing
# ---------------------------------------------------------------------------

def test_extract_nist_control_identifiers():
    ids = security_router.extract_identifiers("Compare AC-1, AC-2(1), GV.OC-01 and PO.1.1")
    assert set(ids["nist_control"]) == {"AC-1", "AC-2(1)", "GV.OC-01", "PO.1.1"}


def test_nist_control_does_not_false_positive_on_random_text():
    ids = security_router.extract_identifiers("This is a normal sentence about IDs and things.")
    assert ids["nist_control"] == []


def test_classify_routes_nist_control_to_exact_lookup():
    decision = security_router.classify("What is AC-1?")
    assert decision["route"] == security_router.ROUTE_EXACT_LOOKUP
    assert decision["identifiers"]["nist_control"] == ["AC-1"]


def test_classify_routes_compliance_topic():
    decision = security_router.classify("how do I implement zero trust architecture")
    assert decision["route"] == security_router.ROUTE_COMPLIANCE


def test_resolve_exact_nist_control_found_and_not_found():
    store.upsert_control({"framework": "sp800-53", "control_id": "AC-1", "parent_id": "AC",
                          "class": "control", "title": "Policy and Procedures",
                          "statement": "Develop policy.", "guidance": "Guide.",
                          "examples_json": None, "external_refs_json": None,
                          "source_url": "https://doi.org/x", "source_title": "NIST SP 800-53",
                          "publisher": "NIST", "version": "5.2.0", "published_date": "2026-01-01"})
    resolved = security_router.resolve_exact({"cve": [], "cwe": [], "capec": [], "attack": [],
                                              "d3fend": [], "nist_control": ["AC-1", "ZZ-99"]})
    found, absent = resolved["nist_control"]
    assert found["found"] is True
    assert found["identifier"] == "AC-1"
    assert absent["found"] is False
    assert absent["control_id"] == "ZZ-99"


# ---------------------------------------------------------------------------
# security_answer.py — grounded, field-driven, never fabricated
# ---------------------------------------------------------------------------

def test_answer_control_never_fabricates_missing_fields():
    rec = {"found": True, "identifier": "AC-1", "framework": "sp800-53",
          "control_id": "AC-1", "parent_id": "AC", "class": "control",
          "title": "Policy and Procedures", "statement": "Develop policy.",
          "guidance": None, "examples": [], "related": [], "children": [],
          "source_url": "https://doi.org/x", "source_title": "NIST SP 800-53",
          "publisher": "NIST", "version": "5.2.0"}
    answer = security_answer._answer_control(rec)
    assert answer["identifier"] == "AC-1"
    assert answer["direct_answer"] == "Develop policy."
    assert "not applicable" in answer["severity_and_exploitation"]
    assert answer["defensive_actions"] == "no separate implementation guidance recorded for this element."
    assert "no related-control" in answer["detection_guidance"]


def test_answer_control_absent_returns_none():
    assert security_answer._answer_control({"found": False, "control_id": "ZZ-99"}) is None


# ---------------------------------------------------------------------------
# graph/builder.py — control relationships never fabricate dangling edges
# ---------------------------------------------------------------------------

def test_control_relationships_only_links_real_records():
    store.upsert_control({"framework": "sp800-53", "control_id": "AC-1", "parent_id": "AC",
                          "class": "control", "title": "Policy", "statement": "Do it.",
                          "guidance": None, "examples_json": None, "external_refs_json": None,
                          "source_url": None, "source_title": None, "publisher": None,
                          "version": None, "published_date": None})
    store.upsert_control({"framework": "sp800-53", "control_id": "IA-1", "parent_id": "IA",
                          "class": "control", "title": "Policy", "statement": "Do it too.",
                          "guidance": None, "examples_json": None, "external_refs_json": None,
                          "source_url": None, "source_title": None, "publisher": None,
                          "version": None, "published_date": None})
    store.replace_links("sp800-53", "AC-1", [
        {"rel": "related", "target_framework": "sp800-53", "target_control_id": "IA-1", "note": None},
        # Points at a control that was never synced — must never become a
        # dangling/fabricated edge in the unified graph.
        {"rel": "related", "target_framework": "sp800-53", "target_control_id": "SC-99", "note": None},
    ])
    nodes, edges = graph_builder._control_relationships()
    node_ids = {n["node_id"] for n in nodes}
    assert "control:sp800-53:AC-1" in node_ids
    assert "control:sp800-53:IA-1" in node_ids
    assert "control:sp800-53:SC-99" not in node_ids
    assert len(edges) == 1
    assert edges[0] == {"src": "control:sp800-53:AC-1", "dst": "control:sp800-53:IA-1",
                        "edge_type": "related_control", "attrs": {}}
