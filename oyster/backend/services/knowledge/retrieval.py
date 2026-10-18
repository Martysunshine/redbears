"""Hybrid, project-aware retrieval for the Knowledge Service.

Fuses two independent retrievers over the installed+enabled Knowledge Packs:

* **vector** similarity (Chroma / all-MiniLM) — semantic recall
* **lexical** full-text (SQLite FTS5, LIKE fallback) — exact term / command recall

The two ranked lists are combined with **reciprocal-rank fusion**, then each
candidate is re-weighted by its source **trust level** and **freshness**,
deduplicated by content hash, diversified so no single pack dominates, and
trimmed to a character **context budget**. Every returned citation carries full
provenance (source url, publisher, licence, section, risk, trust, source_type)
resolved from the SQLite provenance table — so a citation can always be opened
in the source inspector.

Retrieved text is untrusted DATA; this module only ranks and labels it. It never
executes, follows, or trusts instructions embedded in a passage.
"""

from __future__ import annotations

import asyncio
import re
from datetime import datetime, timezone

import config
from services import rag_service

from . import security_aliases, store
from .vulnerabilities import identity as vuln_identity
from .vulnerabilities import store as vuln_store

# The structured vulnerability feeds (CISA KEV / NVD / EPSS / MITRE CWE / MITRE
# CAPEC) embed into their own isolated Chroma collection
# (``oyster_vulnerabilities``, never ``oyster_knowledge`` — see
# services/knowledge/vulnerabilities/), so they need an explicit second vector
# query to compete in this fusion; their SQL provenance already lives in the
# same ``knowledge_chunks``/``knowledge_packs`` tables as every other pack, so
# citation resolution and filtering below need no special-casing.
_VULN_PACK_IDS = {"vulnerability-cve", "mitre-cwe", "mitre-capec"}


async def _empty_list() -> list:
    return []


def _exact_id_chunk_ids(query: str, allowed_vuln_packs: set[str]) -> list[str]:
    """A CVE/CWE/CAPEC id explicitly named in the query (e.g. "Is CVE-2021-44228
    in KEV?") must surface THAT record's chunk, not whichever record happens to
    embed closest — a short alphanumeric id like "CVE-2021-44228" does not
    embed distinctively, so semantic similarity alone has been observed to
    surface a different CVE's data entirely for an exact-id question. This is
    an exact SQL lookup, not a ranking hint, and callers give it precedence
    accordingly."""
    if not allowed_vuln_packs:
        return []
    ids = vuln_identity.find_identifiers(query)
    out: list[str] = []
    if "vulnerability-cve" in allowed_vuln_packs:
        for cve_id in ids.get("cve", []):
            rec = vuln_store.get_vulnerability(cve_id)
            if rec and rec.get("primary_chunk_id"):
                out.append(rec["primary_chunk_id"])
    if "mitre-cwe" in allowed_vuln_packs:
        for cwe_id in ids.get("cwe", []):
            rec = vuln_store.get_cwe(cwe_id)
            if rec and rec.get("primary_chunk_id"):
                out.append(rec["primary_chunk_id"])
    if "mitre-capec" in allowed_vuln_packs:
        for capec_id in ids.get("capec", []):
            rec = vuln_store.get_capec(capec_id)
            if rec and rec.get("primary_chunk_id"):
                out.append(rec["primary_chunk_id"])
    return out


# 2026-09-15: exact-identifier boost for ids that live as ordinary knowledge
# chunks (MITRE ATT&CK technique ids, OWASP LLM Top 10 ids) rather than in the
# separate vuln_store lookup tables CVE/CWE/CAPEC already use. Diagnostic
# evidence: a query naming "T1055" or "T1218" was regularly losing to
# mitre-d3fend-src, whose cross-reference tables mention the SAME id in body
# text without being about it (verified: mitre-attack-src's own T1055/T1218
# pages have the id as the literal document/title prefix, e.g. "T1027.009 —
# Embedded Payloads"; mitre-d3fend-src's matching chunks are titled things
# like "D3FEND — Content Filtering" and only mention the id deep in a table).
# Requiring the id to be the document/title's own prefix — not just present
# anywhere in the body — is what tells a canonical page apart from an
# incidental cross-reference, so the boost is bounded and explainable rather
# than "any mention wins".
_ATTACK_ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b", re.IGNORECASE)
_OWASP_LLM_ID_RE = re.compile(r"\bLLM0?\d{1,2}\b", re.IGNORECASE)
_TITLE_BOOST_ID_RES = (_ATTACK_ID_RE, _OWASP_LLM_ID_RE)
_TITLE_BOOST_FACTOR = 1.25  # bounded multiplier -- nudges, never overrides trust/freshness entirely

# 2026-09-16 (accuracy pass 2): a query naming a specific Windows binary by
# its literal filename ("rundll32.exe") is naming an identifier just as
# precise as a CVE or ATT&CK id -- LOLBAS/GTFOBins-style packs title their
# canonical page for that exact binary ("Rundll32.yml"). Diagnosed cause for
# lolbas-rundll32: the community-trust discount plus single-channel (vector-
# only) presence let broader "official"-trust packs covering the same
# technique in general terms (mitre-attack-src's T1218.011, atomic-red-
# team-src's procedure) outrank the one page that is actually ABOUT this
# specific binary. Keyed on a literal ".exe" mention (not a bare word) to
# keep the false-positive rate negligible -- an English word colliding with
# some unrelated document's filename-style title is not a realistic risk.
_EXE_NAME_RE = re.compile(r"\b([A-Za-z_][\w-]{1,40})\.exe\b", re.IGNORECASE)


def _query_binary_names(query: str) -> set[str]:
    return {m.group(1) for m in _EXE_NAME_RE.finditer(query)}


def _header_matches_id(header: str, ident: str) -> bool:
    """True when ``header`` (a chunk's document/title, already upper-cased) is
    ABOUT ``ident`` specifically -- exact match, or followed by a separator
    (space/dash) -- never a bare prefix match, which would let "T1055.001"
    wrongly match a query that only asked about base technique "T1055"."""
    if header == ident:
        return True
    if not header.startswith(ident):
        return False
    return not header[len(ident):len(ident) + 1].isalnum() and header[len(ident):len(ident) + 1] != "."


def _header_matches_filename(header: str, name: str) -> bool:
    """True when ``header`` is a filename-style title for ``name`` -- e.g.
    "Rundll32.yml" for "rundll32". Same purpose as ``_header_matches_id``, a
    different boundary: these titles are separated by a file extension, not
    a space/dash, so "Rundll32Extractor.md" (name as a bare prefix, no real
    boundary) must not match."""
    stem = header.split(".")[0] if "." in header else header
    return stem.casefold() == name.casefold()


def _query_title_boost_ids(query: str) -> set[str]:
    ids: set[str] = set()
    for pattern in _TITLE_BOOST_ID_RES:
        ids.update(m.group(0).upper() for m in pattern.finditer(query))
    return ids


def _apply_identifier_boost(scored: list[dict], ids, match_fn, lookup_fn,
                            pack_ids: list[str] | None = None, filters: dict | None = None) -> None:
    """Shared boost-or-inject shape behind both ``_apply_title_boost`` (CVE/
    ATT&CK/OWASP-LLM ids, space/dash-delimited) and ``_apply_binary_name_boost``
    (LOLBAS/GTFOBins filenames, dot-delimited): boost any already-fused
    candidate whose own document/title is ABOUT one of ``ids`` per
    ``match_fn``; for any id that matched nothing, fetch its canonical page
    directly via ``lookup_fn`` rather than silently missing it just because a
    high-volume, broadly cross-referencing pack saturated the candidate pool
    first — verified necessary: mitre-d3fend-src's technique tables mention
    an ATT&CK id in dozens of chunks and were filling the entire pool before
    mitre-attack-src's own page for that id ever got a chance to be fused."""
    if not ids:
        return
    present = {i: False for i in ids}
    for prov in scored:
        header = prov.get("title") or prov.get("document") or ""
        matched = [i for i in ids if match_fn(header, i)]
        if matched:
            prov["_score"] = prov.get("_score", 0.0) * _TITLE_BOOST_FACTOR
            for i in matched:
                present[i] = True

    missing = [i for i, found in present.items() if not found]
    if not missing:
        return
    baseline = max((p.get("_score", 0.0) for p in scored), default=0.02)
    seen_ids = {p.get("id") for p in scored}
    for i in missing:
        # limit=3, not 1: more than one pack can legitimately have a canonical
        # page for the same id (e.g. mitre-attack-src's definitional page AND
        # atomic-red-team-src's simulation procedure both title their T1055
        # file "T1055 ..." ) -- injecting only the lookup's first row would
        # arbitrarily pick a winner instead of letting real fusion/diversity
        # decide among genuinely-canonical candidates.
        for prov in lookup_fn(i, pack_ids):
            if prov["id"] in seen_ids or not _passes_filters(prov, filters):
                continue
            prov = dict(prov)
            prov["_score"] = baseline * _TITLE_BOOST_FACTOR
            scored.append(prov)
            seen_ids.add(prov["id"])


def _apply_title_boost(scored: list[dict], ids: set[str],
                        pack_ids: list[str] | None = None, filters: dict | None = None) -> None:
    _apply_identifier_boost(
        scored, ids,
        match_fn=lambda header, i: _header_matches_id(header.upper(), i),
        lookup_fn=lambda i, pids: store.find_chunks_by_title_prefix(i, pids, limit=3),
        pack_ids=pack_ids, filters=filters,
    )


def _apply_binary_name_boost(scored: list[dict], names: set[str],
                              pack_ids: list[str] | None = None, filters: dict | None = None) -> None:
    """Boost-or-inject a query's exact ``.exe`` mention (e.g. "rundll32.exe")
    against a filename-style canonical title (e.g. "Rundll32.yml") -- see
    ``_apply_identifier_boost`` for the shared shape and
    ``store.find_chunks_by_exact_filename_title`` for the dot-delimited
    boundary this needs that the space-delimited id lookup doesn't cover."""
    _apply_identifier_boost(
        scored, names,
        match_fn=_header_matches_filename,
        lookup_fn=lambda n, pids: store.find_chunks_by_exact_filename_title(n, pids, limit=3),
        pack_ids=pack_ids, filters=filters,
    )


def _freshness_weight(meta: dict | None) -> float:
    if not meta:
        return 0.85
    stamp = meta.get("last_reviewed_at") or meta.get("retrieved_at")
    if not stamp:
        return 0.85
    try:
        dt = datetime.fromisoformat(str(stamp).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        age_days = (datetime.now(timezone.utc) - dt).days
    except (ValueError, TypeError):
        return 0.85
    if age_days <= 180:
        return 1.0
    if age_days <= 365:
        return 0.92
    if age_days <= 730:
        return 0.82
    return 0.72


def _trust_weight(trust_level: str | None) -> float:
    return config.KNOWLEDGE_TRUST_WEIGHTS.get(trust_level or "community", 0.80)


def _enrich(chunk_id: str, content: str, pack_id: str | None,
            pack_meta: dict[str, dict]) -> dict:
    """Resolve full provenance for a candidate from the SQLite provenance table,
    falling back to pack-level metadata for chunks indexed before provenance
    tracking existed (keeps older installs working)."""
    prov = store.get_chunk(chunk_id)
    if prov:
        return prov
    meta = pack_meta.get(pack_id or "", {})
    return {
        "id": chunk_id,
        "pack_id": pack_id,
        "pack_version": meta.get("version"),
        "document": meta.get("title"),
        "title": meta.get("title"),
        "publisher": meta.get("security_domain"),
        "canonical_url": (meta.get("source_urls") or "").split(",")[0]
        if isinstance(meta.get("source_urls"), str) else None,
        "licence": meta.get("licence"),
        "trust_level": meta.get("trust_level", "community"),
        "risk_level": meta.get("risk_classification"),
        "domain": meta.get("domain"),
        "section": None,
        "chunk_index": None,
        "content_hash": None,
        "content": content,
        "source_type": "built_in",
    }


def _passes_filters(prov: dict, filters: dict | None) -> bool:
    if not filters:
        return True
    dom = filters.get("domain")
    if dom and (prov.get("domain") or "").lower() != dom.lower():
        return False
    risk = filters.get("risk_level")
    if risk and (prov.get("risk_level") or "").lower() != risk.lower():
        return False
    pub = filters.get("publisher")
    if pub and (prov.get("publisher") or "").lower() != pub.lower():
        return False
    return True


# --- Second-stage lexical reranker ------------------------------------------
# Deliberately NOT a neural cross-encoder: that would need a model download and
# per-query CPU inference (latency + a heavy dependency this offline-first
# design avoids). This rescorer adds the one signal the two first-stage
# retrievers miss — vector search ranks by semantic similarity (bag of meaning),
# bm25 by term frequency (bag of words); neither rewards a passage for covering
# MORE of the query's distinct terms or containing its exact phrases. It is
# bounded (factor in [1, 1+weight]) and runs before the exact-id boosts, so it
# only reorders near-ties and never overrides trust/freshness or an exact match.
_RERANK_STOP = frozenset(
    "the a an and or of to in for how do i use when should it what is are was "
    "with on against into from this that these those your you my can will would "
    "safely lab steps common perform explain write does did not no yes be been "
    "about over under between within across if then else via per".split()
)
_WORD_RE = re.compile(r"[a-z0-9][a-z0-9.\-_]{2,}")


def _content_terms(text: str) -> list[str]:
    return [w for w in _WORD_RE.findall(text.lower()) if w not in _RERANK_STOP]


def _rerank(scored: list[dict], query: str, weight: float) -> None:
    if weight <= 0 or not scored:
        return
    q_terms = _content_terms(query)
    q_set = set(q_terms)
    if not q_set:
        return
    q_bigrams = {f"{q_terms[i]} {q_terms[i + 1]}" for i in range(len(q_terms) - 1)}
    for prov in scored:
        body = (prov.get("content") or "").lower()
        title = (prov.get("title") or prov.get("document") or "").lower()
        if not body:
            continue
        coverage = sum(1 for t in q_set if t in body or t in title) / len(q_set)
        phrase = (sum(1 for bg in q_bigrams if bg in body) / len(q_bigrams)) if q_bigrams else 0.0
        factor = 1.0 + weight * (0.7 * coverage + 0.3 * phrase)
        prov["_score"] = prov.get("_score", 0.0) * factor


def _expand_context(citations: list[dict], radius: int, budget: int) -> list[dict]:
    """Stitch each citation's passage back together with the chunks that
    immediately surround it in its source document. Ingest slices documents into
    ~800-char chunks, so a lone retrieved chunk routinely ends mid-sentence and
    drops the rest of a command/procedure. Expansion stays inside the same
    (pack_id, doc_id), nearest-neighbour first, and stops at ``budget`` total
    chars — so source attribution and project isolation are untouched (every
    added chunk is the same document from the same pack) and the references
    block stays well within the model's context window. Rank order is honoured:
    the most relevant citation is expanded first and gets the most context."""
    if radius <= 0 or not citations:
        return citations
    used = sum(len(c.get("chunk") or "") for c in citations)
    for c in citations:
        if used >= budget:
            break
        center = store.get_chunk(c.get("chunk_id"))
        if not center or center.get("chunk_index") is None:
            continue
        neighbors = store.neighbor_chunks(
            center.get("pack_id"), center.get("doc_id"), center["chunk_index"], radius)
        if not neighbors:
            continue
        pieces = {center["chunk_index"]: center.get("content") or c.get("chunk") or ""}
        added = 0
        for n in sorted(neighbors, key=lambda n: abs(n["chunk_index"] - center["chunk_index"])):
            body = n.get("content") or ""
            if not body or used + added + len(body) > budget:
                continue
            pieces[n["chunk_index"]] = body
            added += len(body)
        if added == 0:
            continue
        c["chunk"] = "\n".join(pieces[i] for i in sorted(pieces))
        c["expanded_chunks"] = len(pieces)
        used += added
    return citations


async def retrieve(query: str, *, top_k: int | None = None, pack_id: str | None = None,
                   filters: dict | None = None, include_disabled: bool = False,
                   budget_chars: int | None = None, expand: bool = True) -> list[dict]:
    top_k = top_k or config.KNOWLEDGE_DEFAULT_TOP_K
    pool = config.KNOWLEDGE_CANDIDATE_POOL

    # Which packs are in play — enabled set unless a specific pack is requested.
    if pack_id:
        enabled = set(store.enabled_pack_ids())
        if not include_disabled and pack_id not in enabled:
            return []
        pack_ids = [pack_id]
    else:
        pack_ids = store.enabled_pack_ids()
        if not pack_ids and not include_disabled:
            return []
        pack_ids = pack_ids or None

    pack_meta = store.pack_meta_map()

    # Only bother querying the vulnerability collection when a vulnerability
    # pack is actually in play for this request (respects pack-scoped search
    # and disabled packs exactly like the knowledge collection does).
    allowed_vuln_packs = _VULN_PACK_IDS if pack_ids is None else (_VULN_PACK_IDS & set(pack_ids))

    # Alias/nickname expansion (e.g. "Log4Shell" -> also search "CVE-2021-44228",
    # "Entra" -> also search "Azure AD") -- additive only, never replaces the
    # original query text, so a query with no recognized alias is byte-for-byte
    # unchanged. See services/knowledge/security_aliases.py for the reviewable
    # table and the diagnostic evidence behind each entry.
    search_query = security_aliases.expand_query(query)

    vec, lex, vuln_vec = await asyncio.gather(
        rag_service.vector_search_knowledge_async(search_query, pool, pack_ids),
        asyncio.to_thread(store.lexical_search, search_query, pack_ids, pool),
        rag_service.vector_search_vulnerabilities_async(search_query, pool) if allowed_vuln_packs
        else _empty_list(),
    )
    vuln_vec = [
        {"id": h["id"], "content": h.get("content", ""), "pack_id": (h.get("metadata") or {}).get("knowledge_pack")}
        for h in vuln_vec
        if (h.get("metadata") or {}).get("knowledge_pack") in allowed_vuln_packs
    ]

    # Reciprocal-rank fusion.
    k = config.KNOWLEDGE_RRF_K
    fused: dict[str, dict] = {}

    def _add(cand_id: str, content: str, cand_pack: str | None, rank: int, weight: float):
        entry = fused.get(cand_id)
        rrf = weight / (k + rank)
        if entry is None:
            fused[cand_id] = {"id": cand_id, "content": content, "pack_id": cand_pack, "rrf": rrf}
        else:
            entry["rrf"] += rrf
            if not entry.get("content"):
                entry["content"] = content

    # vuln_vec is its own independently-ranked vector source (same retrieval
    # method/weight as vec, just a second isolated collection), so it gets its
    # own 0-indexed rank rather than being appended after vec's ranks.
    for rank, c in enumerate(vec):
        _add(c["id"], c.get("content", ""), c.get("pack_id"), rank, config.KNOWLEDGE_VECTOR_WEIGHT)
    for rank, c in enumerate(vuln_vec):
        _add(c["id"], c.get("content", ""), c.get("pack_id"), rank, config.KNOWLEDGE_VECTOR_WEIGHT)
    for rank, c in enumerate(lex):
        _add(c["id"], c.get("content", ""), c.get("pack_id"), rank, config.KNOWLEDGE_LEXICAL_WEIGHT)

    # Re-weight by trust + freshness, resolve provenance, apply filters.
    scored: list[dict] = []
    for cid, entry in fused.items():
        prov = _enrich(cid, entry["content"], entry.get("pack_id"), pack_meta)
        if not _passes_filters(prov, filters):
            continue
        pmeta = pack_meta.get(prov.get("pack_id") or "", {})
        final = entry["rrf"] * _trust_weight(prov.get("trust_level")) * _freshness_weight(pmeta)
        prov["_score"] = final
        scored.append(prov)

    # Second-stage lexical rerank (query-term coverage + exact phrases) — runs
    # BEFORE the identifier boosts below so an exact CVE/ATT&CK/LOLBAS match
    # still wins; bounded so it only reorders near-ties.
    _rerank(scored, query, config.KNOWLEDGE_RERANK_WEIGHT)

    # Bounded boost for a MITRE ATT&CK / OWASP LLM id explicitly named in the
    # query, toward whichever candidate's OWN document/title is that id's
    # canonical page — see _apply_title_boost's docstring-comment for why this
    # beats a plain "id appears anywhere in body" check.
    _apply_title_boost(scored, _query_title_boost_ids(query), pack_ids, filters)
    _apply_binary_name_boost(scored, _query_binary_names(query), pack_ids, filters)

    # A CVE/CWE/CAPEC id explicitly named in the query (including via an alias
    # expansion, e.g. "Log4Shell" -> "CVE-2021-44228") always outranks
    # everything else — see ``_exact_id_chunk_ids``. Boost it if the fusion
    # already found it; otherwise fetch and inject it directly, since an
    # authoritative exact match must never be silently absent just because
    # embedding similarity didn't surface it.
    exact_ids = _exact_id_chunk_ids(search_query, allowed_vuln_packs)
    if exact_ids:
        top = max((p["_score"] for p in scored), default=0.0) + 1.0
        present = {p["id"]: p for p in scored}
        for i, cid in enumerate(exact_ids):
            boosted_score = top + (len(exact_ids) - i)  # preserve relative order among multiple ids
            if cid in present:
                present[cid]["_score"] = boosted_score
            else:
                prov = store.get_chunk(cid)
                if prov and _passes_filters(prov, filters):
                    prov = dict(prov)
                    prov["_score"] = boosted_score
                    scored.append(prov)

    scored.sort(key=lambda x: x["_score"], reverse=True)

    # Dedup by content hash (keep the best), then diversify + budget.
    seen_hashes: set[str] = set()
    per_pack: dict[str, int] = {}
    budget = budget_chars or config.KNOWLEDGE_CONTEXT_BUDGET_CHARS
    used = 0
    out: list[dict] = []
    overflow: list[dict] = []

    for prov in scored:
        h = prov.get("content_hash") or (prov.get("content") or "")[:120]
        if h in seen_hashes:
            continue
        seen_hashes.add(h)
        pid = prov.get("pack_id") or "?"
        if per_pack.get(pid, 0) >= config.KNOWLEDGE_MAX_PER_PACK:
            overflow.append(prov)
            continue
        per_pack[pid] = per_pack.get(pid, 0) + 1
        out.append(prov)

    # Fill remaining slots from overflow (diversity cap relaxed) once each pack
    # has had its share.
    out = out + overflow
    citations: list[dict] = []
    for prov in out:
        if len(citations) >= top_k:
            break
        content = prov.get("content") or ""
        if used + len(content) > budget and citations:
            continue
        used += len(content)
        citations.append(_citation(prov, len(citations) + 1))

    # Stitch each citation back together with the text that surrounds it in its
    # source document (same pack_id + doc_id — attribution/isolation preserved),
    # so passages stop ending mid-command. Applied last, in rank order.
    if expand:
        _expand_context(citations, config.KNOWLEDGE_NEIGHBOR_RADIUS,
                        config.KNOWLEDGE_EXPAND_BUDGET_CHARS)
    return citations


async def retrieve_reranked(query: str, *, top_k: int | None = None, pack_id: str | None = None,
                            filters: dict | None = None) -> tuple[list[dict], dict]:
    """Existing retrieval -> Nemotron rerank -> selected evidence.

    Retrieval runs unchanged but over a wider candidate window (and without
    context expansion). The reranker picks ``top_k`` of them; only the survivors
    are then expanded with their neighbouring text, exactly as before. Citation
    numbers are reassigned in the new order; chunk_id/source metadata ride along.
    On any rerank failure the first ``top_k`` candidates are used in their
    existing order under the original context budget."""
    from services import rerank_service
    top_k = top_k or config.KNOWLEDGE_DEFAULT_TOP_K
    n_cand = max(top_k, config.NEMOTRON_RERANK_CANDIDATES)
    cands = await retrieve(query, top_k=n_cand, pack_id=pack_id, filters=filters,
                           budget_chars=n_cand * 1200, expand=False)
    selected, info = await rerank_service.rerank(query, cands, top_k)

    if info["status"] != "ran":
        # Reproduce the un-reranked selection rule: same char budget as retrieve().
        budget, used, kept = config.KNOWLEDGE_CONTEXT_BUDGET_CHARS, 0, []
        for c in cands:
            if len(kept) >= top_k:
                break
            size = len(c.get("chunk") or "")
            if used + size > budget and kept:
                continue
            used += size
            kept.append(c)
        selected = kept
        info["returned"] = len(selected)

    for i, c in enumerate(selected, 1):
        c["n"] = i
    _expand_context(selected, config.KNOWLEDGE_NEIGHBOR_RADIUS, config.KNOWLEDGE_EXPAND_BUDGET_CHARS)
    return selected, info


def _citation(prov: dict, number: int) -> dict:
    return {
        "n": number,
        "chunk_id": prov.get("id"),
        "document": prov.get("document") or prov.get("title") or "knowledge",
        "chunk": prov.get("content"),
        "score": round(float(prov.get("_score", 0.0)), 4),
        "source_type": prov.get("source_type", "built_in"),
        "knowledge_pack": prov.get("pack_id"),
        "pack_version": prov.get("pack_version"),
        "source_title": prov.get("title"),
        "source_url": prov.get("canonical_url"),
        "publisher": prov.get("publisher"),
        "licence": prov.get("licence"),
        "domain": prov.get("domain"),
        "section": prov.get("section"),
        "risk_level": prov.get("risk_level"),
        "trust_level": prov.get("trust_level"),
    }


def resolve_citation(chunk_id: str) -> dict | None:
    """Full source-inspector payload for one citation."""
    prov = store.get_chunk(chunk_id)
    if not prov:
        return None
    return {
        "chunk_id": prov["id"],
        "knowledge_pack": prov.get("pack_id"),
        "pack_version": prov.get("pack_version"),
        "document": prov.get("document"),
        "title": prov.get("title"),
        "publisher": prov.get("publisher"),
        "canonical_url": prov.get("canonical_url"),
        "licence": prov.get("licence"),
        "trust_level": prov.get("trust_level"),
        "risk_level": prov.get("risk_level"),
        "domain": prov.get("domain"),
        "section": prov.get("section"),
        "chunk_index": prov.get("chunk_index"),
        "content_hash": prov.get("content_hash"),
        "source_type": prov.get("source_type", "built_in"),
        "passage": prov.get("content"),
    }
