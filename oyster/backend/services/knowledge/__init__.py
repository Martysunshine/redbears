"""Knowledge Service — curated, versioned, global cybersecurity Knowledge Packs.

- ``registry``     — discover packs on disk + parse manifests
- ``pack_service`` — install/uninstall (index into the knowledge RAG collection),
                     track install state in SQLite, search + ask with citations

Packs are GLOBAL built-in resources (not project-scoped). The LLM reasons over
retrieved pack content with source attribution — it is never the database.
"""
