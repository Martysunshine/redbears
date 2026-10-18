"""Exported-report sources must carry meaningful titles + identifiers, mapping
the fields RAG/Knowledge citations actually emit (regression for the 2026-10-07
'every source prints as bare "Source"' bug)."""
from services import user_findings_service as ufs


def test_knowledge_citation_gets_title_pack_and_url():
    line = ufs._citation_line(1, {
        "source_title": "Nmap Reference Guide", "source_url": "https://nmap.org/book",
        "knowledge_pack": "nmap-docs", "pack_version": "7.9", "chunk_id": "kp::nmap-docs::x::0"})
    assert "Nmap Reference Guide" in line
    assert "https://nmap.org/book" in line
    assert "nmap-docs 7.9" in line and "bare" not in line.lower()


def test_project_doc_citation_uses_filename_and_type():
    line = ufs._citation_line(2, {"document": "recon_note.md", "artifact_type": "document",
                                  "chunk_id": "art::1::2"})
    assert "recon_note.md" in line and "art::1::2" in line


def test_citation_without_fields_is_not_bare_source_word():
    line = ufs._citation_line(1, {"source_title": "", "document": ""})
    assert "Untitled source" in line  # explicit, not the old generic "Source"


def test_report_lists_titled_sources():
    report = ufs.format_report([{
        "title": "SMB finding", "severity": "high", "content": "x",
        "citations": [{"source_title": "HackTricks SMB", "source_url": "https://h", "knowledge_pack": "hacktricks"}],
    }], "proj-1")
    # Renamed 2026-10-14 ("Sources" -> "Supporting evidence") when the report
    # export started including the actual cited passage, not just a label.
    assert "**Supporting evidence:**" in report
    assert "HackTricks SMB" in report and "hacktricks" in report
