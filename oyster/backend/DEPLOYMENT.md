# Oyster Knowledge Base — portable deployment

The verified knowledge base (**106,045** eligible chunks) lives in `data/memory.db`
(~1.2 GB) and `data/vector_db` (~942 MB). These are **deliberately not in Git**. A
`git pull` gives another machine the code, tests and display logic but **zero chunks**.
This document is how you get the chunks onto Martin's machine and the deployment server.

> **Honest scoping:** the claim is proven **for an installation that has this data**.
> Until a target is populated by one of the paths below, say _"verified in our active
> Oyster knowledge store,"_ not _"available in every deployment."_

There are two paths. **Snapshot restore is the primary, exact, fast path.** Reproducible
rebuild is the fallback when you cannot move the file.

---

## Path A — Snapshot restore (recommended: exact + fast)

Moves the exact verified store out-of-band (never through Git).

> **The restore step REPLACES the target's knowledge base. It does not add to it.**
> `restore_knowledge` DROPs all 33 KB tables and swaps the whole `vector_db`
> directory. Point it at an empty or scratch store, never at a populated
> production data directory, and never while a container is serving that
> directory. The script now refuses both cases without `--force`; run it with
> `--dry-run` first, and take a verified backup before you go anywhere near a
> real store:
>
> ```bash
> python3 scripts/backup_knowledge.py --data <data dir> --dest <elsewhere> --archive
> ```

**Privacy — precisely what is and is not filtered.** The SQLite side is filtered:
only knowledge/vulnerability/graph/controls tables are included, and every
operator-personal table (conversations, user memories, findings, projects,
execution history, training, datasets) is excluded and asserted absent.

The Chroma vector store is **not** filtered. `package_knowledge` archives the
whole `vector_db` directory, so it carries every collection in it, not only the
knowledge ones. On the production store that is four collections, two of which
are not knowledge:

| collection | rows | what ships |
|---|---|---|
| `oyster_knowledge` | 96,991 | intended |
| `oyster_dataset_eval` | 3,999 | eval content |
| `oyster_user_memory` | 65 | embeddings + `{project_id, type}`; the stored text is a fixed-length placeholder, so memory **content** does not travel |
| `oyster_docs` | 12 | **real uploaded document text** — verified by stored-text lengths of 325/800/158/325/141, where 800 is exactly Oyster's chunk size |

So a package built from a store containing uploaded documents carries that
document text. Treat every package as sensitive: encrypt it, and do not put one
on a presigned URL or any channel you would not send the source documents over.

### 1. Build the package (on the machine that HAS the data)

```bash
cd oyster/backend && source venv/bin/activate
# stop the backend first so nothing is writing to the DB
python -m scripts.package_knowledge            # -> data/packages/oyster-kb-<stamp>.tar.zst (+ .sha256)
# or, to encrypt for an untrusted channel:
OYSTER_PKG_PASSPHRASE='<strong-passphrase>' python -m scripts.package_knowledge --encrypt
```

Output (gitignored): the archive (~0.6 GB compressed), a `.sha256` sidecar, and an
internal `manifest.json` (per-file sha256 + audit summary + git commit + embedding model).

### 2. Transfer out-of-band (never commit it)

Choose a secure channel: `scp`, an S3 presigned URL, or an encrypted drive. If you did
not use `--encrypt`, prefer an already-encrypted channel. Send the `.sha256` too.

```bash
scp data/packages/oyster-kb-<stamp>.tar.zst* user@target:/tmp/
```

### 3. Restore on the target (Martin's machine / deployment server)

Stop the backend first — and confirm it, do not assume it. The script's in-use
check is best-effort: SQLite grants an exclusive lock whenever no other
connection is mid-write, so an idle-but-running backend passes it. Renaming
`vector_db` does not stop a running process; it keeps writing through its open
handles into the renamed directory, and those writes are lost.

```bash
docker compose stop oyster-backend               # or however this target runs it
cd oyster/backend && source venv/bin/activate

# 1. See what would happen. Writes nothing.
python -m scripts.restore_knowledge --package /tmp/oyster-kb-<stamp>.tar.zst --dry-run

# 2. Only once the dry run shows an empty or expendable target:
python -m scripts.restore_knowledge --package /tmp/oyster-kb-<stamp>.tar.zst
# encrypted:
OYSTER_PKG_PASSPHRASE='<passphrase>' python -m scripts.restore_knowledge --package /tmp/oyster-kb-<stamp>.tar.zst.enc --decrypt
```

Restore verifies the archive checksum (refusing outright if the `.sha256`
sidecar is missing — it used to warn and continue), verifies every file against
the manifest, copies any existing `memory.db` aside and renames any existing
`vector_db` aside, then **DROPs and repopulates the 33 KB tables** and puts the
package's `vector_db` in place, and re-runs the audit.

Tables outside `KB_TABLES` — conversations, user memories, settings — are not
dropped. But they are left pointing at a vector store that has just been
replaced underneath them, so target-side documents and memories can reference
embeddings that no longer exist. "Personal data is preserved" is true of the
rows and not of what they resolve to.

Both `.bak-*` copies land beside the originals, so the target needs free space
for a second copy of the whole store before you start.

### 4. Confirm the count on the target

```bash
python -m scripts.audit_knowledge               # expect RESULT: PASS (>= 100,000)
```

### 5. Confirm Oyster answers from the restored KB

```bash
uvicorn main:app --port 8001 &                  # start the backend on the target
curl -s localhost:8001/knowledge/metrics/public # -> "106,045 indexed knowledge chunks", threshold met
curl -s -X POST localhost:8001/knowledge/intelligence/ask \
  -H 'Content-Type: application/json' \
  -d '{"question":"What is CVE-2021-44228 Log4Shell?"}'   # grounded, cited answer from the restored store
```

---

## Path B — Reproducible rebuild from source (fallback: no large transfer)

Rebuilds the KB from primary upstreams using the pinned refs in
[`deploy/pinned_sources.json`](deploy/pinned_sources.json). No data secrets move, but it
is **network-bound and slow** (hours), depends on upstream availability (NVD rate-limits
with HTTP 429/503), and may not reproduce byte-identical counts.

```bash
cd oyster/backend && source venv/bin/activate
python -m scripts.reingest_all --list          # show pinned sources
python -m scripts.reingest_all --connectors    # install doc/rule connectors
python -m scripts.reingest_all --all           # + structured vulnerability sync (long)
python -m scripts.audit_knowledge              # confirm >= 100,000
```

It is idempotent (deterministic ids + upserts) and resumable — re-run to continue after a
rate-limit interruption.

---

## Merge & release checklist (before `main`)

1. Review branch `oyster/verified-100k-knowledge` (code + tests + docs only; no DB).
2. Merge to `main` when ready — the merge ships **tooling**, not chunks.
3. Populate each target via Path A (or Path B) — this is the step that actually delivers
   the 106,045 chunks; it does **not** happen via `git pull`.
4. Run `python -m scripts.audit_knowledge` on each target and keep the JSON report.
5. Confirm a grounded `/knowledge/intelligence/ask` answer on each target.

## What is never committed

`data/` (databases, `vector_db`, `packages/`, `reports/`, uploads, artifacts),
`knowledge_src/`, `.env`, model weights, downloaded upstream archives — all covered by
`.gitignore`. Committed: source, tests, docs, the eval-suite JSON, and
`deploy/pinned_sources.json` (small, non-personal reproducibility metadata).
