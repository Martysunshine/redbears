# Oyster — Local AI Security Assistant

A fully local AI assistant and knowledge base for an internal red-team, extended into an
**authorization-aware cybersecurity operating system**. Chat, RAG over your own documents,
curated + live-ingested security knowledge, scope-gated red-team workflows, and a real
(sandboxed, audited) tool-execution engine — all running on your own machine. No cloud APIs,
no telemetry, nothing leaves the box.

> Built for an authorized internal security team. Scope enforcement, approval gates, and audit
> logging are load-bearing, not decorative — read [Scope & Safety](#scope--safety) before use.

---

## Stack

| Layer      | Tech                                              |
|------------|----------------------------------------------------|
| Frontend   | Next.js 14 · TypeScript · Tailwind CSS            |
| Backend    | FastAPI · Python 3.10+ · uvicorn                  |
| LLM        | dolphin3 via Ollama (local, port 11434)           |
| Vision     | qwen2.5vl (image/video understanding, via Ollama) |
| Speech     | faster-whisper (local audio transcription)        |
| Embeddings | sentence-transformers all-MiniLM-L6-v2 (local)    |
| Vector DB  | ChromaDB (persistent, cosine space)               |
| Storage    | SQLite (memory, projects, execution, training)    |

## Ports

| Service  | Port  |
|----------|-------|
| Frontend | 3001  |
| Backend  | 8001  |
| Ollama   | 11434 |

---

## Prerequisites

1. **Ollama** installed and running — https://ollama.com
2. Models pulled:
   ```bash
   ollama pull dolphin3
   ollama pull qwen2.5vl:7b   # optional — image/video understanding
   ```
3. **Python 3.10+**, **Node.js 18+**
4. Optional, for extra tool coverage: `brew install nmap ffmpeg tesseract`

---

## Setup & Run

```bash
# Terminal 1 — Ollama
ollama serve

# Terminal 2 — Backend
cd backend
python3 -m venv venv
source venv/bin/activate        # Windows: venv\Scripts\activate
pip install -r requirements.txt
uvicorn main:app --reload --port 8001

# Terminal 3 — Frontend
cd frontend
npm install
npm run dev
```

- Frontend: **http://localhost:3001**
- Backend: **http://localhost:8001**
- Interactive API docs (every endpoint, live): **http://localhost:8001/docs**

> First document/image upload and first RAG query download local models on demand
> (embeddings ~90 MB, cached after). Nothing is fetched again after that.

---

## Project Structure

```
oyster/
├── backend/
│   ├── main.py                 # app factory — mounts routers, inits DBs
│   ├── config.py                # single source of truth: paths, ports, models, limits
│   ├── routers/                 # HTTP surface (chat, rag, documents, artifacts, scope,
│   │                             #   redteam, findings, execution, knowledge, datasets,
│   │                             #   evaluation, user_memory, training, settings, projects…)
│   ├── services/                 # business logic (RAG, scope, projects, execution, memory…)
│   ├── mcp_server/               # tool registry (network/API/security-test/AI-security/
│   │                             #   malware-analysis/report tools) + agent loop
│   ├── services/execution/       # sandboxed, scope+approval-gated tool execution engine
│   ├── services/knowledge/       # curated packs + live source connectors + retrieval
│   ├── services/user_memory/     # encrypted per-project long-term memory
│   ├── services/training/        # disabled-by-default, consent-gated LoRA pipeline
│   ├── prompts/                  # editable system/mode prompts (hot-reloaded)
│   ├── data/                     # local state — vector DB, uploads, SQLite (gitignored)
│   └── requirements.txt
├── security_kb/                  # optional standalone security-knowledge RAG mount
└── frontend/src/{app,components,lib,types}
```

---

## Core API

Full endpoint list and request/response shapes: **http://localhost:8001/docs**

### Chat & documents

```bash
curl -X POST http://localhost:8001/chat \
  -H "Content-Type: application/json" \
  -d '{"prompt": "Hello, how are you?"}' --no-buffer

curl -X POST http://localhost:8001/documents/upload -F "file=@/path/to/report.pdf"

curl -X POST http://localhost:8001/rag/chat \
  -H "Content-Type: application/json" \
  -d '{"prompt": "What does the document say about X?"}'
```

`/chat` streams plain text. `/rag/chat` returns an answer plus citations
(`document`, `chunk`, `score`) from your uploaded documents.

### Scope & red-team workflow

Every red-team endpoint is **scope-gated** — nothing runs against a target that hasn't been
explicitly authorized.

```bash
curl -X POST http://localhost:8001/scope/set -H "Content-Type: application/json" -d '{
  "engagement_name": "Test", "authorized_by": "Me",
  "start_date": "2026-05-17", "end_date": "2026-06-17",
  "domains": ["*.corp.local"], "ip_ranges": ["192.168.1.0/24"], "repositories": []
}'

curl -X POST http://localhost:8001/redteam/plan -H "Content-Type: application/json" \
  -d '{"target": "api.corp.local", "objective": "Find auth vulnerabilities"}'

curl -X POST http://localhost:8001/code/review -H "Content-Type: application/json" \
  -d '{"target": "github.com/corp/app", "language": "python", "code": "..."}'

curl -X POST http://localhost:8001/findings/report -H "Content-Type: application/json" \
  -d '{"findings": [...]}'
```

Out-of-scope targets don't get a bare refusal — they get full methodology + a local-lab
reproduction path + the scope fields needed to authorize the real target, and the attempt is
logged (`scope_violation`) to `backend/logs/audit.log`.

### Smoke test

```bash
cd backend && python -m pytest -q
```

---

## Feature Overview

Everything below is real, tested, and reachable at `/docs` — this section is a map, not the
full reference (see `CLAUDE.md` for implementation depth on any of these).

- **Projects** (`/projects`) — the aggregate root. Conversations, artifacts, scope, memory, and
  execution history are all project-scoped; switching the active project switches all of them.
- **Artifact ingestion** (`/projects/{id}/artifacts`) — upload files, whole folders, images, and
  video into project RAG. Images get vision-model analysis + OCR + safe EXIF; video gets
  transcription (Whisper), keyframe sampling, and a searchable per-segment timeline with
  timestamp citations.
- **Knowledge Packs & Connectors** (`/knowledge`) — curated, versioned, source-attributed
  security knowledge (OWASP WSTG/API/ASVS/MASTG, MITRE ATT&CK, GTFOBins, LOLBAS, Sigma, YARA,
  Atomic Red Team, WADComs, and more), kept in its own retrieval index so it never blends with
  your private documents. Hybrid vector+lexical retrieval, licence-gated installs, update
  checks, citation inspection, and a cross-source **knowledge graph** linking ATT&CK techniques
  to their emulation (Atomic) and detection (Sigma) coverage.
- **Execution Engine** (`/execution`) — the boundary between "the model talks about a tool" and
  "a tool actually runs." A deterministic pipeline (outside the LLM) validates scope, classifies
  risk, requires explicit approval for anything beyond read-only, runs tools as sandboxed
  argv-only subprocesses (no shell), and captures hashed, redacted evidence for every execution.
- **Long-term Memory** (`/projects/{id}/memory`) — Oyster remembers useful facts and preferences
  across conversations per project, encrypted at rest, deduplicated, conflict-aware, and fully
  editable/exportable/deletable from Settings. This is retrieval, never training.
- **Dataset RAG** (`/datasets`) — a small number of licence-cleared, operator-approved security
  datasets made searchable (clearly labeled, never treated as an authoritative source).
- **Training pipeline** (`/training`) — a separate, **disabled-by-default**, consent-gated LoRA
  fine-tuning pipeline. No conversation ever enters it without an explicit per-project opt-in,
  and it never touches Knowledge Packs or Dataset RAG content.
- **Settings** — one place to control memory, auto-save, ask-before-saving, training consent,
  and delete-all-personal-data, all backed by the APIs above (no hidden state).

---

## Scope & Safety

- Red-team endpoints refuse to operate until `POST /scope/set` has been called for the active
  project, and every target is checked against it (`backend/services/scope_service.py` /
  `backend/services/execution/scope_engine.py`) — CIDR match for IPs, exact-or-subdomain match
  for domains (never substring), path allow-lists, testing window/expiry.
  Violations are logged, not silently dropped.
- The **Execution Engine** is the only place a real command runs. It classifies every tool
  action into a risk class (read-only → destructive), blocks destructive-by-default actions,
  and requires explicit approval bound to the exact target/params before executing — no
  unrestricted shell access exists anywhere in the stack.
- Training data is opt-in per project and off by default; evaluation-only datasets are enforced
  as evaluation-only in code, not just in policy text.
- Everything is logged to `backend/logs/` (`audit.log`, `tool_calls.jsonl`, `agent.jsonl`,
  `memory.jsonl`, `errors.jsonl`) for accountability.

---

## Environment Variables

All defaults live in `backend/config.py` and are overridable via env vars — see
`backend/.env.example` for the full, documented list (ports, models, RAG/embedding tuning,
media limits, knowledge-connector limits, memory encryption, dataset RAG, training pipeline).
Nothing is required to get started; every value has a sensible local default.

**frontend/.env.local**
```
NEXT_PUBLIC_API_URL=http://localhost:8001
```

---

## Keyboard Shortcuts

| Action       | Shortcut        |
|--------------|-----------------|
| Send message | `Enter`         |
| New line     | `Shift + Enter` |

---

Built locally, runs privately. No cloud. No telemetry.
