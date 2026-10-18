"""Evaluation harness for the Knowledge Service (Phase 8).

Measures *retrieval quality* of the installed knowledge against locally-authored
eval suites — deterministic, offline-capable, and governance-gated:

* **Training stays globally disabled.** Nothing here fine-tunes a model; the
  harness only *reads* retrieval output and scores it.
* Suites are local JSON authored for content Oyster actually imported (they are
  not scraped datasets). Any suite that references a registry dataset is checked
  against ``knowledge_registries/datasets.json`` governance and refused unless
  that dataset is evaluation-eligible — and dataset content is never stored as
  knowledge.

Metrics per case: pack-hit, source-hit, first-hit rank (→ MRR), result count,
citation presence. A run is persisted to SQLite (``memory.db``) for history.
"""
