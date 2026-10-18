# Oyster Security KB — Setup Guide

## What this is

A modular RAG knowledge base for the Oyster security assistant. It clones high-signal
public security repositories, cleans and chunks the content, generates embeddings with
`all-MiniLM-L6-v2`, and stores everything in a ChromaDB collection called `security_kb`.

The Oyster FastAPI backend automatically mounts `/kb/*` endpoints when the KB is present.

---

## Directory layout

```
security_kb/
├── config.py                    ← all paths, chunk settings, repo lists
├── requirements.txt
├── .env.example → .env
├── data/
│   ├── raw/
│   │   ├── owasp/               ← OWASP repos cloned here
│   │   ├── tools/               ← tool docs + PayloadsAllTheThings + SecLists
│   │   ├── labs/                ← Juice Shop, WebGoat, DVWA
│   │   ├── writeups/            ← HackTricks, pentest-book, local writeups
│   │   └── ai_security/         ← garak, promptfoo, AI security repos
│   └── vector_store/            ← ChromaDB persistent store
├── scripts/
│   ├── pipeline/
│   │   ├── clean.py             ← HTML strip, whitespace, dedup
│   │   ├── chunk.py             ← recursive splitter
│   │   ├── metadata.py          ← auto-tags: attack_type, severity, difficulty
│   │   └── embed.py             ← SentenceTransformer + ChromaDB upsert / query
│   ├── ingest/
│   │   ├── owasp.py             ← OWASP WSTG, CheatSheets, API Top 10, Top 10, LLM Top 10
│   │   ├── tools.py             ← nuclei-templates, nmap, ffuf, amass, subfinder, trivy …
│   │   ├── labs.py              ← Juice Shop, WebGoat, DVWA
│   │   ├── writeups.py          ← HackTricks, pentest-book, bugbounty-cheatsheet + local/
│   │   └── ai_security.py       ← garak, promptfoo, Awesome-AI-Security
│   ├── run_ingest.py            ← main runner (clone + clean + embed)
│   └── reindex.py               ← wipe vector store and re-embed without re-cloning
└── api/
    └── kb_routes.py             ← FastAPI router mounted at /kb
```

---

## First-time setup

```bash
cd oyster/security_kb

# create and activate a venv (or reuse the backend venv)
python3 -m venv venv
source venv/bin/activate

pip install -r requirements.txt

# copy env template
cp .env.example .env
```

---

## Run full ingestion

```bash
# from oyster/security_kb/
python scripts/run_ingest.py
```

This clones every repo, cleans the text, chunks it, embeds it, and upserts into ChromaDB.

**Expected time:** 20–60 minutes depending on download speed (repos are large).
**Expected size:** ~2–5 GB raw data, ~500 MB vector store.

### Ingest a subset only

```bash
python scripts/run_ingest.py owasp ai_security
python scripts/run_ingest.py tools writeups
```

Available sources: `owasp` `tools` `labs` `writeups` `ai_security`

### Custom chunk size

```bash
python scripts/run_ingest.py --chunk-size 800 --overlap 150
```

---

## Add your own writeups

Drop `.md` or `.txt` files into:

```
security_kb/data/raw/writeups/local/
```

Then run:

```bash
python scripts/run_ingest.py writeups
```

The pipeline auto-detects and tags them as `category: writeups, tool: local_writeups`.

---

## Reindex without re-cloning

If you change `EMBEDDING_MODEL` or `CHUNK_SIZE` in `.env`:

```bash
python scripts/reindex.py
```

This wipes the vector store and re-embeds all already-downloaded raw files.
Pass `--no-wipe` to add/update without wiping.

---

## API endpoints (mounted at /kb in Oyster backend)

### Semantic search

```bash
curl -X POST http://localhost:8001/kb/search \
  -H "Content-Type: application/json" \
  -d '{
    "query": "SQL injection bypass WAF using encoding",
    "top_k": 5,
    "min_score": 0.35
  }'
```

### Filtered search

```bash
# filter by category + attack type
curl -X POST http://localhost:8001/kb/search \
  -H "Content-Type: application/json" \
  -d '{
    "query": "prompt injection via indirect user input",
    "top_k": 8,
    "category": "ai_security",
    "attack_type": "llm"
  }'
```

### Context block for LLM injection

```bash
curl -X POST http://localhost:8001/kb/prompt-context \
  -H "Content-Type: application/json" \
  -d '{
    "query": "IDOR via predictable object IDs in REST API",
    "top_k": 6,
    "category": "owasp"
  }'
```

The response `context` field is a pre-formatted text block you paste directly into a model prompt.

### Stats

```bash
curl http://localhost:8001/kb/stats
# {"collection":"security_kb","total_documents":92347}
```

---

## Metadata schema (per chunk)

| Field        | Example                            | Notes                              |
|--------------|------------------------------------|------------------------------------|
| `source`     | `/data/raw/owasp/wstg/docs/...`    | Full path to source file           |
| `category`   | `owasp`                            | owasp / tools / labs / writeups / ai_security |
| `tool`       | `wstg`                             | Repo or tool name                  |
| `attack_type`| `sqli, xss`                        | Auto-detected, comma-separated     |
| `difficulty` | `intermediate`                     | beginner / intermediate / advanced |
| `language`   | `markdown`                         | File language/extension            |
| `tags`       | `owasp, sqli, high`                | Union of all labels, comma-separated |
| `chunk_index`| `3`                                | Position within the source file    |
| `chunk_count`| `12`                               | Total chunks from this file        |

---

## Tuning tips

**Retrieval quality low?**
- Increase `CHUNK_SIZE` to 1500 for longer context documents (WSTG chapters)
- Add `min_score: 0.4` to filter noise
- Use `category` filter to restrict search space

**Too slow to ingest?**
- Run sources in batches: `owasp` first (most important), then `tools`, then the rest
- Reduce `BATCH_SIZE` in `.env` if you're hitting OOM

**Model upgrade?**
- Swap `EMBEDDING_MODEL` in `.env` to `all-mpnet-base-v2` for higher quality (2× slower)
- Then `python scripts/reindex.py` to rebuild with new embeddings
