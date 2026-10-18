"""Cross-source knowledge graph over the installed Knowledge Packs.

Joins independently-imported sources on the shared MITRE ATT&CK technique id
(the one identifier that appears across ATT&CK STIX, Atomic Red Team and Sigma):

    ATT&CK technique  ──mapped_by──▶   mitre-attack-*   (authoritative definition)
    ATT&CK technique  ──emulated_by──▶ atomic-red-team  (adversary emulation test)
    ATT&CK technique  ──detected_by──▶ sigma            (detection rule)
    sub-technique     ──child_of────▶  parent technique

From that graph it answers purple-team coverage questions ("for T1003.001, which
sources give me mapping / emulation / detection?") and surfaces cross-source
inconsistencies (a Sigma/Atomic reference to a technique that is absent from the
imported ATT&CK set — a dangling reference; or techniques covered for detection
but not emulation, and vice-versa).

Everything is derived deterministically from the ``knowledge_chunks`` provenance
table — no LLM, no network. Rebuilds are idempotent.
"""
