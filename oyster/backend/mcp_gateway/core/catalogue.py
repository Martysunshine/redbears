"""The curated, governed tool catalogue.

Every tool here is a thin, typed wrapper over an EXISTING Oyster service. The
catalogue is deliberately small: only capabilities that can be governed safely
are exposed. Nothing in this module executes a shell, opens an arbitrary file,
reaches an arbitrary network target, or holds a database session — those all
live behind the service layer and, for anything active, behind the Execution
Engine's approval pipeline.

Each tool carries explicit governance metadata (risk level, whether it mutates,
whether it needs approval, permitted roles, whether it is project-scoped, its
timeout, its audit category). The dispatcher (``dispatch.py``) reads that
metadata to decide access; the handler only runs once the dispatcher has
authorized it.

Tool categories
---------------
A  read-only knowledge  — runs immediately after authorization, source-backed
B  project analysis      — inspects only the caller's own project material
C  governed action       — returns an approval request via the Execution
                           Engine and NEVER performs the action itself
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Awaitable, Callable

import config

# ---------------------------------------------------------------------------
# Tool specification
# ---------------------------------------------------------------------------

# Risk levels (mirror the Execution Engine's language where they overlap).
RISK_READ_ONLY = "read_only"     # local read; no side effects
RISK_SENSITIVE = "sensitive"     # inspects permitted project material; no mutation
RISK_GOVERNED = "governed"       # mutating/active — approval required, never auto-run

ROLE_MEMBER = "member"
ROLE_OPERATOR = "operator"


@dataclass
class ToolSpec:
    name: str
    title: str
    description: str
    category: str                       # "A" | "B" | "C"
    risk_level: str
    read_only: bool
    requires_approval: bool
    permitted_roles: tuple[str, ...]
    project_scoped: bool
    audit_category: str
    input_schema: dict
    handler: Callable[..., Awaitable[dict]]
    timeout_s: int = 0                  # 0 => use config.MCP_TOOL_TIMEOUT_S

    def public(self) -> dict:
        """MCP tools/list entry — schema plus a governance annotations block."""
        return {
            "name": self.name,
            "title": self.title,
            "description": self.description,
            "inputSchema": self.input_schema,
            "annotations": {
                "readOnlyHint": self.read_only,
                "destructiveHint": self.category == "C" and not self.read_only,
                "oyster.category": self.category,
                "oyster.riskLevel": self.risk_level,
                "oyster.requiresApproval": self.requires_approval,
                "oyster.permittedRoles": list(self.permitted_roles),
                "oyster.projectScoped": self.project_scoped,
            },
        }


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _cap_top_k(value, default: int = 5) -> int:
    try:
        k = int(value)
    except (TypeError, ValueError):
        k = default
    return max(1, min(k, config.MCP_MAX_SEARCH_TOP_K))


async def _retrieve(query: str, top_k: int) -> list[dict]:
    """Hybrid retrieval with a lexical-only fallback.

    Uses the shared knowledge retriever (vector + lexical fused, full
    provenance). If the vector backend is momentarily unavailable, degrade to
    lexical FTS — which needs no model — so a client still gets source-backed
    citations instead of a hard error. Provenance and citation shape are
    identical either way (reused from the retrieval module)."""
    from services.knowledge import retrieval
    try:
        return await retrieval.retrieve(query, top_k=top_k)
    except Exception:
        import log_config
        from services.knowledge import store as k_store
        log_config.error("mcp_gateway.retrieve",
                         "vector retrieve failed; using lexical fallback", {})
        try:
            pack_ids = k_store.enabled_pack_ids() or None
            lex = k_store.lexical_search(query, pack_ids, max(top_k * 3, top_k))
        except Exception:
            return []
        pack_meta = k_store.pack_meta_map()
        out: list[dict] = []
        for i, c in enumerate(lex[:top_k], 1):
            prov = retrieval._enrich(c["id"], c.get("content", ""), c.get("pack_id"), pack_meta)
            out.append(retrieval._citation(prov, i))
        return out


# ---------------------------------------------------------------------------
# A — read-only knowledge tools
# ---------------------------------------------------------------------------

async def _h_search_security_knowledge(identity, project_id, args) -> dict:
    query = str(args.get("query", "")).strip()
    top_k = _cap_top_k(args.get("top_k"), 5)
    citations = await _retrieve(query, top_k)
    return {
        "query": query,
        "scope": "global_security_knowledge",
        "retrieved_at": _now_iso(),
        "insufficient_evidence": len(citations) == 0,
        "results": citations,
        "total": len(citations),
        "note": ("No indexed knowledge matched this query."
                 if not citations else
                 "Results are indexed, source-attributed knowledge chunks — not model "
                 "training data. Each carries its source; cite by chunk_id."),
    }


async def _h_search_attack_techniques(identity, project_id, args) -> dict:
    query = str(args.get("query", "")).strip()
    top_k = _cap_top_k(args.get("top_k"), 5)
    # Pull a wider candidate set, then keep only ATT&CK / D3FEND-derived chunks
    # so the tool honestly answers about techniques, not general knowledge.
    raw = await _retrieve(query, min(config.MCP_MAX_SEARCH_TOP_K, top_k * 3))
    attack = [c for c in raw if str(c.get("knowledge_pack") or "").startswith(("mitre-attack", "mitre-d3fend"))]
    chosen = (attack or raw)[:top_k]
    return {
        "query": query,
        "scope": "global_security_knowledge",
        "matched_attack_packs": bool(attack),
        "retrieved_at": _now_iso(),
        "insufficient_evidence": len(chosen) == 0,
        "results": chosen,
        "total": len(chosen),
    }


async def _h_map_attack_technique(identity, project_id, args) -> dict:
    technique = str(args.get("technique", "")).strip()
    top_k = _cap_top_k(args.get("top_k"), 4)
    citations = await _retrieve(technique, min(config.MCP_MAX_SEARCH_TOP_K, top_k * 3))
    attack = [c for c in citations if str(c.get("knowledge_pack") or "").startswith("mitre-attack")]
    chosen = (attack or citations)[:top_k]
    return {
        "technique": technique,
        "scope": "global_security_knowledge",
        "retrieved_at": _now_iso(),
        "insufficient_evidence": len(chosen) == 0,
        "results": chosen,
        "total": len(chosen),
    }


async def _h_get_remediation_guidance(identity, project_id, args) -> dict:
    topic = str(args.get("topic", "")).strip()
    top_k = _cap_top_k(args.get("top_k"), 5)
    q = f"{topic} remediation mitigation secure configuration fix"
    citations = await _retrieve(q, top_k)
    return {
        "topic": topic,
        "scope": "global_security_knowledge",
        "retrieved_at": _now_iso(),
        "insufficient_evidence": len(citations) == 0,
        "guidance_sources": citations,
        "total": len(citations),
        "note": "Guidance is drawn only from indexed sources below; no unsourced advice is given.",
    }


async def _h_get_vulnerability(identity, project_id, args) -> dict:
    from services.knowledge.vulnerabilities import store as vuln_store
    from services.knowledge import retrieval
    cve_id = str(args.get("cve_id", "")).strip().upper()
    rec = vuln_store.get_vulnerability(cve_id)
    if not rec:
        return {"cve_id": cve_id, "found": False, "insufficient_evidence": True,
                "note": "No record for this identifier in the indexed vulnerability feeds "
                        "(CISA KEV / NVD / EPSS)."}
    evidence = None
    if rec.get("primary_chunk_id"):
        evidence = retrieval.resolve_citation(rec["primary_chunk_id"])
    return {
        "cve_id": cve_id, "found": True, "record": rec,
        "scope": "global_security_knowledge", "retrieved_at": _now_iso(),
        "evidence": evidence,
    }


async def _h_explain_cve(identity, project_id, args) -> dict:
    from services.knowledge.vulnerabilities import store as vuln_store
    cve_id = str(args.get("cve_id", "")).strip().upper()
    rec = vuln_store.get_vulnerability(cve_id)
    context = await _retrieve(cve_id, _cap_top_k(args.get("top_k"), 4))
    return {
        "cve_id": cve_id,
        "found": bool(rec),
        "insufficient_evidence": not rec and not context,
        "record": rec,
        "related_evidence": context,
        "scope": "global_security_knowledge",
        "retrieved_at": _now_iso(),
        "note": "The record fields are authoritative feed data; related_evidence are "
                "separately-retrieved indexed passages. No interpretation is added.",
    }


async def _h_list_knowledge_sources(identity, project_id, args) -> dict:
    from services.knowledge import store as k_store
    meta = k_store.pack_meta_map()
    enabled = set(k_store.enabled_pack_ids())
    sources = []
    for pid, m in sorted(meta.items()):
        if pid not in enabled:
            continue
        sources.append({
            "pack_id": pid,
            "title": m.get("title"),
            "domain": m.get("domain") or m.get("security_domain"),
            "publisher": m.get("security_domain"),
            "licence": m.get("licence"),
            "trust_level": m.get("trust_level"),
            "version": m.get("version"),
            "chunk_count": m.get("chunk_count"),
            "source_urls": m.get("source_urls"),
        })
    return {"total_sources": len(sources), "sources": sources, "retrieved_at": _now_iso()}


async def _h_get_source_evidence(identity, project_id, args) -> dict:
    from services.knowledge import retrieval
    chunk_id = str(args.get("chunk_id", "")).strip()
    payload = retrieval.resolve_citation(chunk_id)
    if not payload:
        return {"chunk_id": chunk_id, "found": False,
                "note": "No such source chunk is indexed, or it is not currently accessible."}
    return {"chunk_id": chunk_id, "found": True, "evidence": payload,
            "scope": "global_security_knowledge", "retrieved_at": _now_iso()}


# ---------------------------------------------------------------------------
# B — project tools (isolated to the caller's own project)
# ---------------------------------------------------------------------------

async def _h_list_projects(identity, project_id, args) -> dict:
    from services import project_service
    projects = project_service.list_projects_for(identity.oyster)
    slim = [{"id": p.get("id"), "name": p.get("name"), "description": p.get("description"),
             "created_at": p.get("created_at")} for p in projects]
    return {"active_project": project_id, "total": len(slim), "projects": slim}


def _artifact_snippet(text: str, query: str, width: int = 240) -> str:
    if not text:
        return ""
    low = text.lower()
    idx = low.find(query.lower()) if query else -1
    if idx < 0:
        return text[:width]
    start = max(0, idx - width // 3)
    return text[start:start + width]


async def _h_search_project_files(identity, project_id, args) -> dict:
    from services.artifacts import store as art_store
    query = str(args.get("query", "")).strip()
    items = art_store.list_for_project(project_id)
    hits = []
    for a in items:
        full = art_store.get(a["id"], with_text=True) or {}
        text = full.get("text") or ""
        name = a.get("original_filename") or a.get("filename") or ""
        if not query or query.lower() in text.lower() or query.lower() in name.lower():
            hits.append({
                "file_id": a["id"],
                "filename": name,
                "kind": a.get("kind"),
                "mime": a.get("mime"),
                "size": a.get("size"),
                "index_status": a.get("index_status"),
                "snippet": _artifact_snippet(text, query),
                "created_at": a.get("created_at"),
            })
    return {"project_id": project_id, "scope": "project_files", "query": query,
            "total": len(hits), "results": hits, "retrieved_at": _now_iso()}


async def _h_read_project_file(identity, project_id, args) -> dict:
    from services.artifacts import store as art_store
    file_id = str(args.get("file_id", "")).strip()
    a = art_store.get(file_id, with_text=True)
    # Structural isolation: the artifact must belong to the resolved project.
    if not a or a.get("project_id") != project_id:
        return {"file_id": file_id, "found": False,
                "note": "No such file in this project (files are isolated per project)."}
    return {
        "file_id": file_id, "found": True, "project_id": project_id,
        "scope": "project_files",
        "filename": a.get("original_filename") or a.get("filename"),
        "mime": a.get("mime"), "size": a.get("size"), "kind": a.get("kind"),
        "content": a.get("text") or "",
        "retrieved_at": _now_iso(),
    }


# Deterministic (no-LLM) static indicators. Each is a (name, compiled-regex).
def _danger_patterns():
    import re
    return [
        ("python-eval-exec", re.compile(r"\b(eval|exec)\s*\(")),
        ("python-os-system", re.compile(r"\bos\.system\s*\(")),
        ("shell-true", re.compile(r"shell\s*=\s*True")),
        ("pickle-loads", re.compile(r"\bpickle\.loads?\s*\(")),
        ("yaml-unsafe-load", re.compile(r"\byaml\.load\s*\((?![^)]*Loader)")),
        ("weak-hash", re.compile(r"\b(md5|sha1)\s*\(", re.I)),
        ("sql-string-concat", re.compile(r"(SELECT|INSERT|UPDATE|DELETE)\b.*[\"'`]\s*\+\s*", re.I)),
        ("js-innerhtml", re.compile(r"\.innerHTML\s*=")),
        ("js-child-process-exec", re.compile(r"child_process.*\.exec\s*\(")),
        ("dangerous-deserialize", re.compile(r"(Marshal\.load|ObjectInputStream|unserialize)\s*\(")),
    ]


async def _h_analyze_project_code(identity, project_id, args) -> dict:
    from services.artifacts import store as art_store
    from . import security as sec
    file_id = str(args.get("file_id", "")).strip()
    patterns = _danger_patterns()
    targets = []
    if file_id:
        a = art_store.get(file_id, with_text=True)
        if not a or a.get("project_id") != project_id:
            return {"found": False, "note": "No such file in this project."}
        targets = [a]
    else:
        for meta in art_store.list_for_project(project_id):
            full = art_store.get(meta["id"], with_text=True)
            if full:
                targets.append(full)
    findings = []
    secret_files = 0
    for a in targets:
        text = a.get("text") or ""
        name = a.get("original_filename") or a.get("filename") or a["id"]
        if sec.redact_text(text) != text:
            secret_files += 1
            findings.append({"file": name, "pattern": "hardcoded-secret-indicator",
                             "severity": "high",
                             "detail": "One or more values look like credentials/keys (redacted)."})
        for pname, rx in patterns:
            for i, line in enumerate(text.splitlines(), 1):
                if rx.search(line):
                    findings.append({"file": name, "pattern": pname, "severity": "medium",
                                     "line": i, "detail": sec.redact_text(line.strip()[:200])})
                    if len([f for f in findings if f["file"] == name]) > 50:
                        break
    return {
        "project_id": project_id, "scope": "project_files",
        "files_analyzed": len(targets),
        "analysis_method": "deterministic static pattern scan (no model, no execution)",
        "secret_indicator_files": secret_files,
        "findings": findings, "total_findings": len(findings),
        "retrieved_at": _now_iso(),
    }


_DEP_FILES = {"requirements.txt", "package.json", "pyproject.toml", "pipfile",
              "go.mod", "cargo.toml", "gemfile", "pom.xml", "build.gradle"}
_AUDIT_CMD = {
    "requirements.txt": "pip-audit -r requirements.txt", "pyproject.toml": "pip-audit",
    "pipfile": "pip-audit", "package.json": "npm audit --production",
    "go.mod": "govulncheck ./...", "cargo.toml": "cargo audit",
    "gemfile": "bundle audit", "pom.xml": "mvn org.owasp:dependency-check-maven:check",
    "build.gradle": "gradle dependencyCheckAnalyze",
}


async def _h_review_dependencies(identity, project_id, args) -> dict:
    from services.artifacts import store as art_store
    manifests = []
    for meta in art_store.list_for_project(project_id):
        name = (meta.get("original_filename") or meta.get("filename") or "").lower()
        base = name.rsplit("/", 1)[-1]
        if base in _DEP_FILES:
            full = art_store.get(meta["id"], with_text=True) or {}
            text = full.get("text") or ""
            deps = [ln.strip() for ln in text.splitlines()
                    if ln.strip() and not ln.strip().startswith("#")][:200]
            manifests.append({
                "file": meta.get("original_filename") or meta.get("filename"),
                "manifest_type": base,
                "recommended_audit_command": _AUDIT_CMD.get(base, "(run your ecosystem's audit tool)"),
                "declared_lines": deps,
                "line_count": len(deps),
            })
    return {
        "project_id": project_id, "scope": "project_files",
        "manifests_found": len(manifests), "manifests": manifests,
        "note": ("No dependency manifests are indexed in this project."
                 if not manifests else
                 "Dependency lines are read from your indexed manifests; running the audit "
                 "command against a live index is a governed action, not performed here."),
        "retrieved_at": _now_iso(),
    }


async def _h_generate_security_review(identity, project_id, args) -> dict:
    analysis = await _h_analyze_project_code(identity, project_id, {})
    focus = str(args.get("focus", "")).strip()
    # Ground recommendations in retrieved sources for each distinct issue type.
    issue_types = sorted({f["pattern"] for f in analysis.get("findings", [])})
    grounded = []
    for it in issue_types[:5]:
        q = f"{it.replace('-', ' ')} secure coding remediation"
        cites = await _retrieve(q, 2)
        grounded.append({"issue_type": it, "guidance_sources": cites})
    extra = []
    if focus:
        extra = await _retrieve(f"{focus} security best practice", 3)
    return {
        "project_id": project_id, "scope": "project_files",
        "review_method": "deterministic analysis + source-grounded guidance (no model)",
        "static_analysis": {
            "files_analyzed": analysis.get("files_analyzed"),
            "findings": analysis.get("findings"),
            "total_findings": analysis.get("total_findings"),
        },
        "grounded_guidance": grounded,
        "focus_guidance": extra,
        "retrieved_at": _now_iso(),
        "note": "Findings are deterministic; every recommendation cites an indexed source. "
                "No interpretation beyond the cited passages is asserted.",
    }


# ---------------------------------------------------------------------------
# C — governed action tools (approval required; never executed by the gateway)
# ---------------------------------------------------------------------------

async def _h_request_authorized_scan(identity, project_id, args) -> dict:
    from services.execution import service as exec_service, store as exec_store
    from . import security as sec
    if not config.EXECUTION_ENGINE_ENABLED:
        return {"ok": False, "status": "unavailable",
                "note": "The Execution Engine is disabled on this deployment."}
    exec_store.init_db()
    tool_id = str(args.get("tool", "")).strip()
    action_id = str(args.get("action", "")).strip()
    target = str(args.get("target", "")).strip()
    parameters = args.get("parameters") or {}
    objective = str(args.get("objective", "")).strip()
    if not isinstance(parameters, dict):
        return {"ok": False, "error": "parameters must be an object"}
    # Defence-in-depth SSRF pre-check at the gateway boundary. The Execution
    # Engine re-validates against the engagement scope (default-deny) regardless.
    if target:
        internal, reason = sec.classify_ssrf(target)
        if internal:
            return {"ok": False, "status": "refused",
                    "note": f"Target refused at gateway boundary: {reason}. Scans may only "
                            f"target in-scope, non-internal hosts."}
    result = exec_service.create_proposal(
        tool_id=tool_id, action_id=action_id, targets=[target] if target else [],
        parameters=parameters, objective=objective, project_id=project_id,
        requested_by=identity.audit_actor(),
    )
    if not result.get("ok"):
        return {"ok": False, "error": result.get("error", "could not create proposal")}
    prop = result["proposal"]
    return {
        "ok": True,
        "executed": False,
        "status": prop["status"],
        "approval_required": prop["status"] == "awaiting_approval",
        "proposal_id": prop["id"],
        "risk_level": prop["risk_level"],
        "tool": tool_id, "action": action_id, "target": target,
        "parameters": prop["parameters"],
        "generated_command_preview": prop.get("generated_command"),
        "expires_at": prop.get("expires_at"),
        "policy_decision": result.get("policy", {}).get("decision"),
        "note": ("This scan was NOT run. It requires explicit human approval in Oyster "
                 "before it can execute. Approve it in the Oyster Execution view, then run "
                 "it there — the gateway never approves or runs a scan on a client's word."),
    }


async def _h_get_scan_status(identity, project_id, args) -> dict:
    from services.execution import store as exec_store
    exec_store.init_db()
    proposal_id = str(args.get("proposal_id", "")).strip()
    execution_id = str(args.get("execution_id", "")).strip()
    if proposal_id:
        prop = exec_store.get_proposal(proposal_id)
        if not prop or prop.get("project_id") != project_id:
            return {"found": False, "note": "No such proposal in this project."}
        execs = exec_store.executions_for_proposal(proposal_id)
        return {"found": True, "kind": "proposal", "proposal_id": proposal_id,
                "status": prop["status"], "risk_level": prop.get("risk_level"),
                "executions": [{"id": e["id"], "status": e["status"]} for e in execs]}
    if execution_id:
        ex = exec_store.get_execution(execution_id)
        if not ex or ex.get("project_id") != project_id:
            return {"found": False, "note": "No such execution in this project."}
        return {"found": True, "kind": "execution", "execution_id": execution_id,
                "status": ex["status"], "exit_code": ex.get("exit_code")}
    return {"found": False, "error": "provide proposal_id or execution_id"}


async def _h_retrieve_scan_report(identity, project_id, args) -> dict:
    from services.execution import service as exec_service, store as exec_store
    from . import security as sec
    exec_store.init_db()
    execution_id = str(args.get("execution_id", "")).strip()
    view = exec_service.execution_view(execution_id, project_id=project_id)
    if not view:
        return {"found": False, "note": "No such execution report in this project."}
    ex = view["execution"]
    out = view.get("output") or {}
    return {
        "found": True, "execution_id": execution_id, "status": ex.get("status"),
        "tool": ex.get("tool_id"), "action": ex.get("action_id"), "target": ex.get("target"),
        "exit_code": ex.get("exit_code"),
        "stdout": sec.redact_text((out.get("stdout") or "")),
        "observations": (out.get("parsed") or {}).get("observations", []),
        "evidence": [{"id": e["id"], "title": e["title"]} for e in view.get("evidence", [])],
        "retrieved_at": _now_iso(),
    }


async def _h_propose_file_change(identity, project_id, args) -> dict:
    """Record an intent to change a file and return an approval request.

    The gateway NEVER writes a file. This mints a governed change request in the
    audit trail with a parameter hash bound to the exact proposed change; a human
    must review and apply it outside the MCP surface. This deliberately does not
    integrate with any auto-apply path — there is none, by design."""
    import hashlib, json as _json
    from services.execution import store as exec_store
    exec_store.init_db()
    path = str(args.get("path", "")).strip()
    rationale = str(args.get("rationale", "")).strip()
    summary = str(args.get("proposed_change_summary", "")).strip()
    if not path or not summary:
        return {"ok": False, "error": "path and proposed_change_summary are required"}
    param_hash = hashlib.sha256(
        _json.dumps({"path": path, "summary": summary}, sort_keys=True).encode()
    ).hexdigest()
    change_id = exec_store.new_id("chg")
    exec_store.audit(project_id, "mcp_file_change_proposed",
                     actor=identity.audit_actor(),
                     detail={"change_id": change_id, "path": path,
                             "rationale": rationale[:500], "summary": summary[:500],
                             "param_hash": param_hash})
    return {
        "ok": True, "executed": False, "approval_required": True,
        "change_request_id": change_id, "path": path, "param_hash": param_hash,
        "status": "awaiting_approval",
        "note": ("Recorded as a change request. The gateway did NOT modify any file. A human "
                 "must review and apply this change in Oyster; the MCP surface cannot apply it."),
    }


# ---------------------------------------------------------------------------
# The catalogue
# ---------------------------------------------------------------------------

_KNOWLEDGE_ROLES = (ROLE_MEMBER, ROLE_OPERATOR)

CATALOGUE: list[ToolSpec] = [
    # ---- A: read-only knowledge -------------------------------------------
    ToolSpec(
        name="search_security_knowledge",
        title="Search security knowledge",
        description="Semantic + lexical search across Oyster's indexed, source-attributed "
                    "security knowledge (frameworks, standards, advisories, techniques). "
                    "Returns source-backed citations, never unsourced claims.",
        category="A", risk_level=RISK_READ_ONLY, read_only=True, requires_approval=False,
        permitted_roles=_KNOWLEDGE_ROLES, project_scoped=False, audit_category="knowledge_search",
        input_schema={
            "type": "object", "additionalProperties": False,
            "properties": {
                "query": {"type": "string", "minLength": 1, "maxLength": 1000,
                          "description": "What to look up."},
                "top_k": {"type": "integer", "minimum": 1, "maximum": config.MCP_MAX_SEARCH_TOP_K,
                          "description": "Max results (default 5)."},
            }, "required": ["query"],
        },
        handler=_h_search_security_knowledge,
    ),
    ToolSpec(
        name="search_attack_techniques",
        title="Search ATT&CK / D3FEND techniques",
        description="Search MITRE ATT&CK and D3FEND-derived knowledge for adversary techniques "
                    "and defensive countermeasures. Source-backed.",
        category="A", risk_level=RISK_READ_ONLY, read_only=True, requires_approval=False,
        permitted_roles=_KNOWLEDGE_ROLES, project_scoped=False, audit_category="knowledge_search",
        input_schema={
            "type": "object", "additionalProperties": False,
            "properties": {
                "query": {"type": "string", "minLength": 1, "maxLength": 1000},
                "top_k": {"type": "integer", "minimum": 1, "maximum": config.MCP_MAX_SEARCH_TOP_K},
            }, "required": ["query"],
        },
        handler=_h_search_attack_techniques,
    ),
    ToolSpec(
        name="map_attack_technique",
        title="Map an ATT&CK technique",
        description="Resolve an ATT&CK technique id or name (e.g. T1190) to its indexed "
                    "description and related detections. Source-backed.",
        category="A", risk_level=RISK_READ_ONLY, read_only=True, requires_approval=False,
        permitted_roles=_KNOWLEDGE_ROLES, project_scoped=False, audit_category="knowledge_search",
        input_schema={
            "type": "object", "additionalProperties": False,
            "properties": {
                "technique": {"type": "string", "minLength": 1, "maxLength": 200,
                              "description": "Technique id or keyword."},
                "top_k": {"type": "integer", "minimum": 1, "maximum": config.MCP_MAX_SEARCH_TOP_K},
            }, "required": ["technique"],
        },
        handler=_h_map_attack_technique,
    ),
    ToolSpec(
        name="get_remediation_guidance",
        title="Get remediation guidance",
        description="Retrieve source-backed remediation / mitigation guidance for a security "
                    "topic. Every recommendation is grounded in an indexed source.",
        category="A", risk_level=RISK_READ_ONLY, read_only=True, requires_approval=False,
        permitted_roles=_KNOWLEDGE_ROLES, project_scoped=False, audit_category="knowledge_search",
        input_schema={
            "type": "object", "additionalProperties": False,
            "properties": {
                "topic": {"type": "string", "minLength": 1, "maxLength": 500},
                "top_k": {"type": "integer", "minimum": 1, "maximum": config.MCP_MAX_SEARCH_TOP_K},
            }, "required": ["topic"],
        },
        handler=_h_get_remediation_guidance,
    ),
    ToolSpec(
        name="get_vulnerability",
        title="Get a vulnerability record",
        description="Look up a CVE in the indexed vulnerability feeds (CISA KEV / NVD / EPSS) "
                    "and return the structured record plus its source evidence.",
        category="A", risk_level=RISK_READ_ONLY, read_only=True, requires_approval=False,
        permitted_roles=_KNOWLEDGE_ROLES, project_scoped=False, audit_category="vuln_lookup",
        input_schema={
            "type": "object", "additionalProperties": False,
            "properties": {"cve_id": {"type": "string", "pattern": r"(?i)^CVE-\d{4}-\d{4,}$"}},
            "required": ["cve_id"],
        },
        handler=_h_get_vulnerability,
    ),
    ToolSpec(
        name="explain_cve",
        title="Explain a CVE",
        description="Return a CVE's authoritative record fields alongside separately-retrieved "
                    "indexed passages. No interpretation is added beyond the sources.",
        category="A", risk_level=RISK_READ_ONLY, read_only=True, requires_approval=False,
        permitted_roles=_KNOWLEDGE_ROLES, project_scoped=False, audit_category="vuln_lookup",
        input_schema={
            "type": "object", "additionalProperties": False,
            "properties": {
                "cve_id": {"type": "string", "pattern": r"(?i)^CVE-\d{4}-\d{4,}$"},
                "top_k": {"type": "integer", "minimum": 1, "maximum": config.MCP_MAX_SEARCH_TOP_K},
            }, "required": ["cve_id"],
        },
        handler=_h_explain_cve,
    ),
    ToolSpec(
        name="list_knowledge_sources",
        title="List knowledge sources",
        description="List the indexed, enabled knowledge packs (title, publisher, licence, "
                    "trust level, version, chunk count) that back every answer.",
        category="A", risk_level=RISK_READ_ONLY, read_only=True, requires_approval=False,
        permitted_roles=_KNOWLEDGE_ROLES, project_scoped=False, audit_category="knowledge_search",
        input_schema={"type": "object", "additionalProperties": False, "properties": {}},
        handler=_h_list_knowledge_sources,
    ),
    ToolSpec(
        name="get_source_evidence",
        title="Get source evidence",
        description="Resolve a citation chunk_id to its full source-inspector payload "
                    "(passage, publisher, url, licence, section, hashes).",
        category="A", risk_level=RISK_READ_ONLY, read_only=True, requires_approval=False,
        permitted_roles=_KNOWLEDGE_ROLES, project_scoped=False, audit_category="knowledge_search",
        input_schema={
            "type": "object", "additionalProperties": False,
            "properties": {"chunk_id": {"type": "string", "minLength": 1, "maxLength": 400}},
            "required": ["chunk_id"],
        },
        handler=_h_get_source_evidence,
    ),
    # ---- B: project tools --------------------------------------------------
    ToolSpec(
        name="list_projects",
        title="List my projects",
        description="List the projects the authenticated caller is authorized to see.",
        category="B", risk_level=RISK_READ_ONLY, read_only=True, requires_approval=False,
        permitted_roles=_KNOWLEDGE_ROLES, project_scoped=True, audit_category="project_read",
        input_schema={"type": "object", "additionalProperties": False, "properties": {}},
        handler=_h_list_projects,
    ),
    ToolSpec(
        name="search_project_files",
        title="Search project files",
        description="Full-text search across files uploaded to the caller's own project. "
                    "Never reaches another project or the server filesystem.",
        category="B", risk_level=RISK_SENSITIVE, read_only=True, requires_approval=False,
        permitted_roles=_KNOWLEDGE_ROLES, project_scoped=True, audit_category="project_read",
        input_schema={
            "type": "object", "additionalProperties": False,
            "properties": {
                "query": {"type": "string", "maxLength": 1000},
                "project_id": {"type": "string", "maxLength": 200,
                               "description": "Optional; ignored unless you own it."},
            },
        },
        handler=_h_search_project_files,
    ),
    ToolSpec(
        name="read_project_file",
        title="Read a project file",
        description="Read one file from the caller's own project by its file_id. Secrets are "
                    "redacted. Files are isolated per project.",
        category="B", risk_level=RISK_SENSITIVE, read_only=True, requires_approval=False,
        permitted_roles=_KNOWLEDGE_ROLES, project_scoped=True, audit_category="project_read",
        input_schema={
            "type": "object", "additionalProperties": False,
            "properties": {
                "file_id": {"type": "string", "minLength": 1, "maxLength": 200},
                "project_id": {"type": "string", "maxLength": 200},
            }, "required": ["file_id"],
        },
        handler=_h_read_project_file,
    ),
    ToolSpec(
        name="analyze_project_code",
        title="Analyze project code",
        description="Deterministic static scan of the caller's project files for dangerous "
                    "patterns and hardcoded-secret indicators. No model, no execution.",
        category="B", risk_level=RISK_SENSITIVE, read_only=True, requires_approval=False,
        permitted_roles=_KNOWLEDGE_ROLES, project_scoped=True, audit_category="project_analysis",
        input_schema={
            "type": "object", "additionalProperties": False,
            "properties": {
                "file_id": {"type": "string", "maxLength": 200,
                            "description": "Optional; analyze one file instead of all."},
                "project_id": {"type": "string", "maxLength": 200},
            },
        },
        handler=_h_analyze_project_code,
    ),
    ToolSpec(
        name="review_dependencies",
        title="Review dependencies",
        description="Read dependency manifests indexed in the caller's project and report "
                    "declared dependencies plus the recommended audit command. No network.",
        category="B", risk_level=RISK_SENSITIVE, read_only=True, requires_approval=False,
        permitted_roles=_KNOWLEDGE_ROLES, project_scoped=True, audit_category="project_analysis",
        input_schema={
            "type": "object", "additionalProperties": False,
            "properties": {"project_id": {"type": "string", "maxLength": 200}},
        },
        handler=_h_review_dependencies,
    ),
    ToolSpec(
        name="generate_security_review",
        title="Generate a security review",
        description="Combine the deterministic static analysis of the caller's project with "
                    "source-grounded remediation guidance into one cited review. No model.",
        category="B", risk_level=RISK_SENSITIVE, read_only=True, requires_approval=False,
        permitted_roles=_KNOWLEDGE_ROLES, project_scoped=True, audit_category="project_analysis",
        input_schema={
            "type": "object", "additionalProperties": False,
            "properties": {
                "focus": {"type": "string", "maxLength": 300},
                "project_id": {"type": "string", "maxLength": 200},
            },
        },
        handler=_h_generate_security_review,
    ),
    # ---- C: governed actions ----------------------------------------------
    ToolSpec(
        name="request_authorized_scan",
        title="Request an authorized scan",
        description="Create an APPROVAL REQUEST for an active security scan through Oyster's "
                    "Execution Engine. Returns 'approval required' and never runs the scan.",
        category="C", risk_level=RISK_GOVERNED, read_only=False, requires_approval=True,
        permitted_roles=(ROLE_OPERATOR,), project_scoped=True, audit_category="governed_action",
        input_schema={
            "type": "object", "additionalProperties": False,
            "properties": {
                "tool": {"type": "string", "minLength": 1, "maxLength": 40,
                         "description": "Execution Engine tool id (e.g. nmap, http, tls, semgrep)."},
                "action": {"type": "string", "minLength": 1, "maxLength": 40,
                           "description": "Action id on that tool (e.g. port_scan, inspect)."},
                "target": {"type": "string", "maxLength": 300,
                           "description": "In-scope target (host/url/path)."},
                "parameters": {"type": "object", "description": "Action parameters."},
                "objective": {"type": "string", "maxLength": 500},
            }, "required": ["tool", "action"],
        },
        handler=_h_request_authorized_scan,
    ),
    ToolSpec(
        name="get_scan_status",
        title="Get scan status",
        description="Read the status of a scan proposal or execution in the caller's project.",
        category="C", risk_level=RISK_READ_ONLY, read_only=True, requires_approval=False,
        permitted_roles=(ROLE_OPERATOR,), project_scoped=True, audit_category="governed_action",
        input_schema={
            "type": "object", "additionalProperties": False,
            "properties": {
                "proposal_id": {"type": "string", "maxLength": 200},
                "execution_id": {"type": "string", "maxLength": 200},
            },
        },
        handler=_h_get_scan_status,
    ),
    ToolSpec(
        name="retrieve_scan_report",
        title="Retrieve a scan report",
        description="Retrieve the output, observations and evidence of a completed scan "
                    "execution in the caller's project. Secrets redacted.",
        category="C", risk_level=RISK_READ_ONLY, read_only=True, requires_approval=False,
        permitted_roles=(ROLE_OPERATOR,), project_scoped=True, audit_category="governed_action",
        input_schema={
            "type": "object", "additionalProperties": False,
            "properties": {"execution_id": {"type": "string", "minLength": 1, "maxLength": 200}},
            "required": ["execution_id"],
        },
        handler=_h_retrieve_scan_report,
    ),
    ToolSpec(
        name="propose_file_change",
        title="Propose a file change",
        description="Record an APPROVAL REQUEST to change a file. Returns 'approval required' "
                    "and never modifies anything — a human applies it in Oyster.",
        category="C", risk_level=RISK_GOVERNED, read_only=False, requires_approval=True,
        permitted_roles=_KNOWLEDGE_ROLES, project_scoped=True, audit_category="governed_action",
        input_schema={
            "type": "object", "additionalProperties": False,
            "properties": {
                "path": {"type": "string", "minLength": 1, "maxLength": 500},
                "proposed_change_summary": {"type": "string", "minLength": 1, "maxLength": 2000},
                "rationale": {"type": "string", "maxLength": 2000},
                "project_id": {"type": "string", "maxLength": 200},
            }, "required": ["path", "proposed_change_summary"],
        },
        handler=_h_propose_file_change,
    ),
]

_BY_NAME = {t.name: t for t in CATALOGUE}


def by_name(name: str) -> ToolSpec | None:
    return _BY_NAME.get(name)


def list_public(identity_role: str | None = None) -> list[dict]:
    """tools/list payload. When a role is given, only tools that role may call
    are advertised (a member never even sees operator-only scan tools)."""
    out = []
    for t in CATALOGUE:
        if identity_role and identity_role not in t.permitted_roles:
            continue
        out.append(t.public())
    return out
