"""Structured vulnerability knowledge: CISA KEV, NVD CVE, FIRST EPSS, MITRE CWE,
MITRE CAPEC — merged by identifier (CVE/CWE/CAPEC id), never by fuzzy match.

Parallel to ``services/knowledge/connectors/`` (git/STIX docs) rather than an
extension of it: these sources need row-level incremental upsert and windowed
sync, which the whole-pack "delete everything, reinstall everything" connector
pipeline is not built for at CVE scale. Retrieval-facing text still flows
through the existing ``knowledge_chunks`` table and hybrid retrieval machinery
for citation parity; the structured CVSS/EPSS/KEV/relationship fields live in
their own normalized tables (see ``store.py``).
"""
