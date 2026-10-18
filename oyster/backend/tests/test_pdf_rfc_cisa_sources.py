"""PDF/RFC connector heading detection + CISA CSAF advisory normalization —
pure-function tests, no network."""

from __future__ import annotations

from services.knowledge.connectors.pdf_connector import _is_heading
from services.knowledge.connectors.rfc_connector import _FOOTER_RE, _HEADER_RE, _HEADING_RE
from services.knowledge.vulnerabilities.sources import cisa_csaf


# ---------------------------------------------------------------------------
# PDF heading detection (NIST SP style)
# ---------------------------------------------------------------------------

def test_pdf_heading_detects_numbered_and_dotted_styles():
    assert _is_heading("1 Introduction") == ("1", "Introduction")
    assert _is_heading("1. Introduction") == ("1", "Introduction")
    assert _is_heading("3.1.2 ZTA Using Micro-Segmentation") == ("3.1.2", "ZTA Using Micro-Segmentation")


def test_pdf_heading_rejects_toc_dot_leaders():
    assert _is_heading("3.1.3 Some Section Title ....... 12") is None


def test_pdf_heading_rejects_address_lines():
    assert _is_heading("100 Bureau Drive (Mail Stop 8920) Gaithersburg, MD") is None


def test_pdf_heading_rejects_plain_prose():
    assert _is_heading("This is just a regular sentence.") is None


# ---------------------------------------------------------------------------
# RFC plain-text heading + header/footer stripping
# ---------------------------------------------------------------------------

def test_rfc_heading_matches_two_space_convention():
    m = _HEADING_RE.match("4.1.2.  Client Hello")
    assert m is not None
    assert m.groups() == ("4.1.2", "Client Hello")


def test_rfc_header_footer_regexes_strip_page_furniture():
    text = "RFC 8446                           TLS                       August 2018\nBody text.\nRescorla                     Standards Track                    [Page 2]\n"
    text = _HEADER_RE.sub("", text)
    text = _FOOTER_RE.sub("", text)
    assert "RFC 8446" not in text
    assert "[Page 2]" not in text
    assert "Body text." in text


# ---------------------------------------------------------------------------
# CISA CSAF advisory normalization — never fabricates missing fields
# ---------------------------------------------------------------------------

def test_normalize_advisory_extracts_real_fields():
    raw = {
        "document": {
            "title": "Example Corp Widget",
            "publisher": {"name": "CISA"},
            "tracking": {"initial_release_date": "2026-01-01T00:00:00Z",
                        "current_release_date": "2026-01-02T00:00:00Z"},
        },
        "vulnerabilities": [{
            "cve": "CVE-2026-12345",
            "cwe": {"id": "CWE-306", "name": "Missing Authentication"},
            "notes": [{"category": "summary", "text": "A real description."}],
            "scores": [{"cvss_v3": {"baseScore": 7.5, "baseSeverity": "HIGH",
                                    "vectorString": "CVSS:3.1/AV:N"}}],
            "remediations": [{"details": "Fixed in version 2.0.1."}],
            "references": [{"category": "external", "url": "https://vendor.example/advisory"}],
        }],
    }
    entry = {"advisory_id": "VA-26-001-01", "title": "Example Corp Widget",
             "content_url": "https://raw.githubusercontent.com/.../va-26-001-01.json",
             "source": "cisa-csaf-it"}
    advisory, findings, injection_count = cisa_csaf.normalize_advisory(raw, entry)

    assert advisory["advisory_id"] == "VA-26-001-01"
    assert advisory["publisher"] == "CISA"
    assert advisory["initial_release_date"] == "2026-01-01T00:00:00Z"

    assert len(findings) == 1
    f = findings[0]
    assert f["cve_id"] == "CVE-2026-12345"
    assert f["cwe_id"] == "CWE-306"
    assert f["cvss_score"] == 7.5
    assert f["severity"] == "HIGH"
    assert f["description"] == "A real description."
    assert "Fixed in version 2.0.1." in f["remediation"]
    assert f["fixed_version"] == "Fixed in version 2.0.1."
    assert f["vendor_reference_url"] == "https://vendor.example/advisory"
    assert injection_count == 0


def test_normalize_advisory_never_fabricates_absent_cve():
    raw = {"document": {"title": "No CVE here"}, "vulnerabilities": [{"notes": []}]}
    entry = {"advisory_id": "ICSA-26-001-01", "title": "No CVE here",
             "content_url": "https://example/x.json", "source": "cisa-csaf-ot"}
    advisory, findings, _ = cisa_csaf.normalize_advisory(raw, entry)
    assert findings == []  # no cve field -> dropped, never invented
