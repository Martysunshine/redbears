from __future__ import annotations

import hashlib
import asyncio
import json
import re
from typing import AsyncGenerator, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import StreamingResponse

from pydantic import BaseModel

import config
from models.schemas import ChatRequest
from prompt_utils import (
    build_history_messages,
    build_public_system_prompt,
    build_system_prompt,
)
from services import (
    account_deletion,
    chat_quota,
    chat_queue,
    entitlements,
    ollama_service,
    project_context,
    rag_service,
)
from services.auth_service import oauth2_scheme, require_chat_access
from services.training import user_consent
from services.user_memory import service as memory_service
from services.chat_policy import classify, is_continuation, named_reference_subject, identifier_ask_subject
from services.knowledge.vulnerabilities import identity as vuln_identity
from services.knowledge.vulnerabilities import store as vuln_store

# The PUBLIC chat surface. Mounted WITHOUT the admin gate (see main.py) —
# require_chat_access in each route signature decides the caller's tier:
#   admin → free model choice, memory from the active project, no caps
#   user  → same, but memory comes from their own workspace (project_context);
#           chat requires a current agreement acceptance
#   anon  → forced public model, prompt-length cap, per-IP daily allowance,
#           then 429 "anon_daily_limit"; no memory, no custom system prompt
# Do not add routes here without deciding their tier story explicitly.
router = APIRouter(tags=["chat"])


class TrainingConsentRequest(BaseModel):
    allowed: bool


def _owner_key(identity: dict) -> str:
    """Who owns a chat job. Hashed for anonymous callers — the queue has no
    business holding raw IPs, and the value is only ever compared, never read."""
    if identity.get("tier") == "anon":
        ip = identity.get("ip") or "unknown"
        return "ip:" + hashlib.sha256(ip.encode()).hexdigest()[:16]
    return "sub:" + (identity.get("sub") or "")


def _owned_job(job_id: str, identity: dict) -> chat_queue.ChatJob:
    """Fetch a job the caller actually owns.

    404 for someone else's job, never 403 — a distinguishable "exists but not
    yours" turns job ids into an oracle. Same rule as conversations.py and
    artifacts.py.
    """
    job = chat_queue.queue.get(job_id)
    if job is None or job.owner != _owner_key(identity):
        raise HTTPException(status_code=404, detail="job_not_found")
    return job


async def _ndjson_view(job: chat_queue.ChatJob) -> AsyncGenerator[str, None]:
    """The framed view: queue position while waiting, then tokens."""
    def frame(obj: dict) -> str:
        return json.dumps(obj, separators=(",", ":")) + "\n"

    yield frame({"type": "job", "id": job.id})
    sent = 0
    started = False
    async for snap in chat_queue.queue.watch(job):
        if snap["status"] == chat_queue.QUEUED:
            # Also re-sent on every heartbeat: the position is still true, and
            # the bytes keep the connection alive through any proxy.
            yield frame({"type": "queue", "position": snap["position"],
                         "ahead": snap["ahead"], "eta_seconds": snap["eta_seconds"]})
            continue
        if not started:
            started = True
            yield frame({"type": "start"})
        if snap.get("heartbeat"):
            # Nothing changed (a model loading, a slow first token). Unknown
            # frame types are ignored by the frontend's consumeFrames.
            yield frame({"type": "keepalive"})
            continue
        text = snap["text"]
        if len(text) > sent:
            yield frame({"type": "token", "t": text[sent:]})
            sent = len(text)
        if snap["status"] == chat_queue.DONE:
            yield frame({"type": "done"})
        elif snap["status"] == chat_queue.ERROR:
            yield frame({"type": "error",
                         "detail": snap["error"] or "Oyster couldn't finish that answer. Please try again."})
        elif snap["status"] == chat_queue.CANCELLED:
            # `code` is additive: an older client sees the same error frame
            # it always did; the new stream controller reads the code and
            # ends the bubble as "stopped" instead of "failed".
            yield frame({"type": "error", "detail": "cancelled", "code": "cancelled"})


# Defense-in-depth, not the primary fix: the Modelfile now carries real stop
# tokens (<|im_start|>/<|im_end|>/"\nUser:"/"\nAssistant:") so Ollama itself
# should stop before ever emitting one of these. This catches the rare case
# where a model ignores its stop tokens and starts hallucinating a NEW turn
# ("User: ...", "Assistant: ...") onto the end of a real answer — see
# oyster/docs/AI_HANDOFF.md 2026-09-30.
_TRANSCRIPT_LEAK_RE = re.compile(r"\n\s*(?:User|Assistant)\s*:\s", re.IGNORECASE)


def _truncate_at_leaked_turn(text: str) -> str:
    m = _TRANSCRIPT_LEAK_RE.search(text)
    return text[: m.start()] if m else text


async def _raw_view(job: chat_queue.ChatJob) -> AsyncGenerator[str, None]:
    """The legacy view: bare tokens, byte-for-byte what clients get today.

    A queued caller receives only a single space every CHAT_STREAM_HEARTBEAT_S
    until their turn: enough bytes to keep a proxy from severing the
    connection, and whitespace every renderer collapses. It is sent only
    before the first token, so the answer itself is never altered.
    """
    sent = 0
    async for snap in chat_queue.queue.watch(job):
        text = snap["text"]
        if len(text) > sent:
            yield text[sent:]
            sent = len(text)
        elif snap.get("heartbeat") and sent == 0:
            yield " "


# The three read/write handlers for the account itself (`me` and the consent
# pair) are plain ``def``: each does synchronous SQLite work and awaits
# nothing, so as ``async def`` that work ran on the event loop and a contended
# write stalled every chat stream in flight. FastAPI runs a plain ``def`` in
# its threadpool, where blocking is harmless. ``delete_me`` and ``chat`` stay
# ``async`` because they await; their sync calls are pushed off the loop
# individually with ``run_in_threadpool``. tests/test_router_sync_rule.py
# pins this.


@router.get("/me")
def me(identity: dict = Depends(require_chat_access)):
    """Tier probe for the frontend UI (never consumes anon quota)."""
    out: dict = {"tier": identity["tier"]}
    if identity["tier"] == "anon":
        limit = config.ANON_CHAT_DAILY_LIMIT
        out["daily_limit"] = limit
        out["remaining_today"] = max(0, limit - chat_quota.used_today(identity["ip"]))
    else:
        out["email"] = identity.get("email")
        state = user_consent.get(identity.get("sub") or "")
        # Drives the UI toggle AND the "is my data used?" notice under the
        # composer, so the app can never claim something the DB contradicts.
        out["training_consent"] = state["allowed"]
        out["agreement"] = _agreement_view(state, identity["tier"])
    return out


def _agreement_view(state: dict, tier: str) -> dict:
    """What the frontend needs to decide whether to show the blocking gate.

    ``required`` is what makes an unaccepted account see a modal it cannot
    dismiss; operators are exempt (they are the controller, not a user of
    someone else's service), so the gate never traps the people who would
    have to fix it if it broke.
    """
    return {
        "required": tier == "user",
        "accepted": state["allowed"],
        "accepted_version": state["consent_version"],
        "accepted_at": state["updated_at"],
        "current_version": state["current_version"],
    }


@router.delete("/me")
async def delete_me(identity: dict = Depends(require_chat_access)):
    """Erase this account's data — the self-service side of the erasure right.

    Only removes what Oyster owns; the Supabase login record is deleted by the
    client calling Supabase's own security-definer function, so the
    service_role key never has to exist on this box (see
    services/account_deletion.py).
    """
    tier = identity["tier"]
    if tier == "anon":
        # Nothing to erase: anonymous chats are never stored server-side. Their
        # history is in their own browser, and clearing it is already theirs to do.
        raise HTTPException(status_code=401, detail="Sign in to delete your account")
    if tier == "admin":
        # Operator data is entangled with real engagement projects (scope,
        # findings, evidence, the shared memory store) and is not confined to
        # a per-account sandbox, so a public delete button would take out far
        # more than the person pressing it expects.
        raise HTTPException(
            status_code=403,
            detail="Operator accounts cannot be deleted from here — contact the administrator.",
        )
    return await account_deletion.purge_account(identity.get("sub") or "",
                                                identity.get("email"))


@router.get("/me/training-consent")
def get_training_consent(identity: dict = Depends(require_chat_access)):
    """This account's acceptance of the current user agreement."""
    if identity["tier"] == "anon":
        # Nothing to accept: anonymous chats are never stored server-side and
        # can never enter a dataset, so there is no agreement to record.
        return {"allowed": False, "eligible": False,
                "reason": "Anonymous chats are never stored or used for training."}
    state = user_consent.get(identity.get("sub") or "")
    return {**state, "eligible": True,
            "agreement": _agreement_view(state, identity["tier"])}


@router.put("/me/training-consent")
def set_training_consent(
    request: TrainingConsentRequest, identity: dict = Depends(require_chat_access)
):
    """Accept the agreement, or withdraw it.

    Withdrawal is immediate for every dataset built afterwards, and — because
    acceptance is what grants access to the free tier — it also ends chat
    access until the user accepts again. The UI states both before confirming;
    models already trained cannot be untrained.
    """
    if identity["tier"] == "anon":
        raise HTTPException(status_code=401, detail="Sign in to manage your data preferences")
    state = user_consent.set_allowed(
        identity.get("sub") or "", request.allowed, identity.get("email")
    )
    return {"status": "ok", **state,
            "agreement": _agreement_view(state, identity["tier"])}


@router.post("/chat")
async def chat(request: ChatRequest, http_request: Request,
               identity: dict = Depends(require_chat_access),
               # The caller's raw bearer token, taken straight from the same
               # scheme require_chat_access verifies. Needed because Oyster asks
               # VoiceIQ about this user's plan by FORWARDING their own token —
               # it holds no service key and can therefore never ask about
               # anybody else. Never logged, never stored, never put on a job.
               # Named `bearer`, not `token`: `run()` below already uses `token`
               # for a generated LLM token, and two very different things under
               # one name inside nested scopes is a trap for the next reader.
               bearer: Optional[str] = Depends(oauth2_scheme)):
    tier = identity["tier"]

    if tier == "admin":
        # Operators keep the registry default as their fallback.
        ollama_model = config.resolve_model(request.model)
    elif tier == "user":
        # Signed-in accounts still pick freely from MODEL_REGISTRY — the
        # heavier models are simply slow (~65s to first token for an 8B on
        # this 2-core box vs a few seconds for the 3B), and that is the account
        # holder's trade-off to make.
        #
        # What changed is the FALLBACK. resolve_model() defaults an unknown key
        # to the registry default (an 8B), so a stale frontend, a replayed
        # request or a typo silently pulled 5 GB of weights and evicted the
        # pinned public model. An unrecognised key now lands on the small
        # model instead: an unclear request should cost the box the least, not
        # the most.
        ollama_model = (config.AVAILABLE_MODELS.get(request.model)
                        or config.PUBLIC_CHAT_MODEL
                        or config.resolve_model(config.DEFAULT_MODEL))
    else:
        # Anonymous visitors always run the public model — letting strangers
        # swap 5-6GB models in and out would thrash the CPU box for everyone,
        # and the public model is deliberately a small/fast one.
        # PUBLIC_CHAT_MODEL is a raw Ollama model name so it can point at
        # anything pulled on the host; empty falls back to the registry default.
        ollama_model = config.PUBLIC_CHAT_MODEL or config.resolve_model(config.DEFAULT_MODEL)
        if len(request.prompt) > config.ANON_CHAT_MAX_PROMPT_CHARS:
            raise HTTPException(
                status_code=413,
                detail=f"Prompt too long (max {config.ANON_CHAT_MAX_PROMPT_CHARS} characters)",
            )

    if tier == "user":
        # The free tier is offered on the condition that conversations may be
        # stored and used to improve the model. No current acceptance → no
        # chat. Enforced HERE, not only in the UI: a hidden frontend modal is
        # not a gate, and this is the boundary the training pipeline's promise
        # rests on. Accounts that accepted a superseded version land here too,
        # which is how a terms change reaches people who signed up before it.
        if not await run_in_threadpool(user_consent.has_accepted, identity.get("sub") or ""):
            raise HTTPException(status_code=403, detail="terms_acceptance_required")

    if tier == "anon":
        # PRE-CHECK ONLY — the consume moved to the moment generation actually
        # starts (see `run` below). Consuming here would mean that queueing and
        # then closing the tab burned an anonymous visitor's single message for
        # the day without them ever getting an answer. The atomic consume is
        # still the enforcement point, so nothing is racy: this is just a fast
        # rejection for someone who is already over.
        used = await run_in_threadpool(chat_quota.used_today, identity["ip"])
        if used >= config.ANON_CHAT_DAILY_LIMIT:
            raise HTTPException(
                status_code=429,
                detail="anon_daily_limit",
                headers={"Retry-After": str(chat_quota.seconds_until_utc_midnight())},
            )

    # Anonymous visitors get the lean persona (prefill cost dominates TTFT on
    # CPU) and cannot inject their own system prompt.
    system_prompt = (
        build_system_prompt(request.agent_mode, request.system_prompt)
        if tier != "anon"
        else build_public_system_prompt()
    )

    # Classify the request separately from model generation. This prevents an
    # abliteration/persona change from turning a real third-party target into
    # an operational workflow, while leaving general security knowledge and
    # owned-lab work technically useful.
    # Classify target/authorization from what the USER said, not the assistant's
    # replies: an educational WPA2/SQLi answer naturally mentions "rogue access
    # points"/"stolen credentials", which would otherwise make a legitimate
    # owned-lab follow-up look like a real-third-party request and get boundaried.
    history_text = "\n".join(
        getattr(turn, "content", "") for turn in request.history
        if getattr(turn, "role", "") == "user"
    )
    policy = classify(request.prompt, history_text)
    system_prompt = f"{system_prompt}\n\nREQUEST STATE: {policy.state}\n{policy.instruction}"
    # Short follow-ups ("it", "ig", "yes", "give me code") must resolve from the
    # conversation instead of triggering a "what do you mean?" loop. The small
    # model co-references poorly on its own, so state the rule explicitly across
    # whatever state applies (except a boundary, which replaces generation).
    if request.history and not policy.boundary and is_continuation(request.prompt):
        system_prompt += (
            "\n\nFOLLOW-UP RULE: This turn is a short follow-up. Continue the topic "
            "established in the conversation above — resolve 'it', 'that', 'ig', "
            "'yes', 'give me code/instructions' from that context and answer "
            "directly. Do not ask what it refers to unless the conversation "
            "genuinely leaves it ambiguous."
        )

    # The small local model can confidently invent details for an unfamiliar
    # named tool, flag, CVE, or version. Check the local evidence store before
    # allowing that specific claim to reach generation. This is evidence
    # handling, not a cybersecurity keyword block: ordinary explanations and
    # known references still go directly to the model.
    verification_boundary: str | None = None
    subject = named_reference_subject(request.prompt)
    # A literal CVE/CWE/CAPEC token is itself matched as a "named reference" by
    # the pattern above, but generic top_k=3 SEMANTIC search is a weak evidence
    # source for an exact identifier — it ranks on meaning, not substring match,
    # so a correctly-indexed chunk that literally contains the ID can rank below
    # three unrelated-but-topically-similar chunks and make a real, documented
    # CVE look "unverifiable". Oyster's local vulnerability store is an exact,
    # authoritative index for these tokens, so identifiers are deferred to the
    # identifier-grounding block below instead of this semantic check.
    if subject and (vuln_identity.is_cve(subject) or vuln_identity.is_cwe(subject)
                   or vuln_identity.is_capec(subject)):
        subject = None
    if subject:
        # Retrieval may be cold or contended by a large local index. It must
        # never leave chat hanging; a timeout is treated as missing evidence.
        try:
            evidence = await asyncio.wait_for(
                rag_service.search_knowledge_async(request.prompt, top_k=3),
                timeout=3.0,
            )
        except Exception:
            evidence = []
        # A semantic hit about a related security topic is not evidence for a
        # named product or flag. Require the retrieved record to mention the
        # requested subject (or its exact token) before allowing the model to
        # state product-specific facts. This keeps broad RAG results useful
        # without turning them into invented provenance.
        subject_token = subject.strip("`").split()[-1].lower()
        supported = any(
            subject_token in " ".join(
                str(item.get(field, ""))
                # "chunk" is the retrieved text itself and "source_title" is its
                # document title — both were missing here, so this check only
                # ever looked at filename/source_url metadata and never the
                # actual passage content. Fixed 2026-10-13 (see AI_HANDOFF.md):
                # without "chunk", a subject genuinely documented in the body of
                # a retrieved passage could still be called unverifiable.
                for field in ("title", "content", "document", "source_url",
                             "canonical_url", "chunk", "source_title")
            ).lower()
            for item in evidence
        )
        if not supported:
            verification_boundary = (
                f"I can't verify {subject!r} from Oyster's available evidence, so I won't "
                "invent its features, syntax, affected versions, or output. Provide a "
                "vendor link, exact version, or source and I can analyse it; I can also "
                "explain the underlying security technique using documented tools."
            )

    # Security IDENTIFIER questions ("what CVE is Log4Shell?") get the same
    # confident-recall failure mode as named tools: nothing above catches them
    # because the prompt carries no literal CVE/CWE/CAPEC token to check, so a
    # bare name-of-identifier question reached generation ungrounded and the
    # small model answered from (wrong) memory — e.g. Log4Shell ->
    # CVE-2021-45046, the follow-up DoS CVE, instead of the original
    # CVE-2021-44228. Ground it in retrieved evidence instead; never let the
    # model assert an identifier Oyster cannot show a source for. Skipped when
    # the verification_boundary above already short-circuits generation.
    identifier_grounding: str | None = None
    if not verification_boundary:
        literal_ids = vuln_identity.find_identifiers(request.prompt)
        literal_cves = literal_ids.get("cve") or []
        literal_cwes = literal_ids.get("cwe") or []
        literal_capecs = literal_ids.get("capec") or []
        if literal_cves or literal_cwes or literal_capecs:
            # The prompt already names a specific identifier — ground its facts
            # from Oyster's local authoritative records so the model cannot
            # misstate severity/description/mechanism for an ID it got right.
            lines: list[str] = []
            unresolved: list[str] = []
            for cve_id in literal_cves[:3]:
                rec = await run_in_threadpool(vuln_store.get_vulnerability, cve_id)
                if rec:
                    kev = " — CISA KEV-listed" if rec.get("kev_listed") else ""
                    sev = (f", CVSS v3 {rec['cvss_v3_score']} ({rec['cvss_v3_severity']})"
                          if rec.get("cvss_v3_score") is not None else "")
                    lines.append(f"- {rec['cve_id']}{sev}{kev}: "
                                f"{(rec.get('description') or '')[:280]}")
                else:
                    unresolved.append(cve_id)
            for cwe_id in literal_cwes[:3]:
                rec = await run_in_threadpool(vuln_store.get_cwe, cwe_id)
                if rec:
                    lines.append(f"- {rec.get('cwe_id', cwe_id)}: "
                                f"{(rec.get('name') or rec.get('description') or '')[:280]}")
                else:
                    unresolved.append(cwe_id)
            for capec_id in literal_capecs[:3]:
                rec = await run_in_threadpool(vuln_store.get_capec, capec_id)
                if rec:
                    lines.append(f"- {rec.get('capec_id', capec_id)}: "
                                f"{(rec.get('name') or rec.get('description') or '')[:280]}")
                else:
                    unresolved.append(capec_id)
            parts = []
            if lines:
                parts.append(
                    "VERIFIED RECORD(S) from Oyster's local authoritative store — state "
                    "only what is below for these identifiers; do not add severity, dates, "
                    "or affected-version claims that are not in this record:\n" + "\n".join(lines)
                )
            if unresolved:
                parts.append(
                    f"The identifier(s) {', '.join(unresolved)} are not in Oyster's local "
                    "store. Say that explicitly rather than stating details from memory; "
                    "offer to look it up if given a source."
                )
            identifier_grounding = "\n\n".join(parts)
        else:
            asked_name = identifier_ask_subject(request.prompt)
            if asked_name:
                try:
                    id_evidence = await asyncio.wait_for(
                        rag_service.search_knowledge_async(request.prompt, top_k=6),
                        timeout=3.0,
                    )
                except Exception:
                    id_evidence = []
                name_token = asked_name.split()[0].lower()  # e.g. "log4shell"
                candidates: dict[str, set[str]] = {}  # cve_id -> {source titles}
                for item in id_evidence:
                    text_blob = f"{item.get('chunk','')} {item.get('source_title','')} {item.get('document','')}"
                    if name_token not in text_blob.lower():
                        continue
                    for cve_id in vuln_identity.find_identifiers(text_blob).get("cve", []):
                        candidates.setdefault(cve_id, set()).add(
                            item.get("source_title") or item.get("document") or "knowledge base")
                if not candidates:
                    identifier_grounding = (
                        f"Oyster's retrieved evidence does not confirm a specific CVE/CWE/"
                        f"CAPEC identifier for {asked_name!r}. State plainly that it cannot "
                        "be confirmed from available evidence rather than naming one from "
                        "memory; offer to confirm it if given a source."
                    )
                elif len(candidates) == 1:
                    cve_id = next(iter(candidates))
                    srcs = ", ".join(sorted(next(iter(candidates.values()))))
                    rec = await run_in_threadpool(vuln_store.get_vulnerability, cve_id)
                    extra = f" ({rec.get('cvss_v3_severity')}, CVSS {rec['cvss_v3_score']})" \
                        if rec and rec.get("cvss_v3_score") is not None else ""
                    identifier_grounding = (
                        f"Oyster's retrieved evidence (source: {srcs}) identifies {asked_name} "
                        f"as {cve_id}{extra}. State this identifier; do not state a different "
                        "one from memory."
                    )
                else:
                    listed = ", ".join(sorted(candidates))
                    identifier_grounding = (
                        f"Oyster's retrieved evidence is CONFLICTING or covers multiple distinct "
                        f"issues for {asked_name!r}: {listed}. Say this plainly and list them "
                        "rather than asserting a single identifier; ask which one only if the "
                        "user's question depends on telling them apart."
                    )
    if identifier_grounding:
        system_prompt = f"{system_prompt}\n\n{identifier_grounding}"

    if tier != "anon":
        # Memory is PRIVATE recall from this account's own sessions. The
        # project is resolved from identity (operators → their active project,
        # users → their own workspace), so one account's memories can never be
        # injected into another's chat. Anonymous chat has no memory at all.
        # workspace_id may CREATE the workspace row on a first visit — a
        # write, under the store's lock — so it goes to the threadpool too.
        project_id = await run_in_threadpool(project_context.workspace_id, identity)
        memories = await memory_service.retrieve_relevant(project_id, request.prompt)
        mem_block = memory_service.format_memory_context(memories)
        if mem_block:
            system_prompt = f"{system_prompt}\n\n---\n\n{mem_block}"

    # Follow-up context. /chat used to answer every turn from request.prompt
    # alone, so "and the second one?" arrived with no idea what the first was.
    # For signed-in callers we prepend the prior turns the client sent (its own
    # conversation, budgeted to num_ctx) as REAL messages[] roles — not text
    # flattened into one prompt string (see build_history_messages). Anonymous
    # chat stays historyless — no stored context, lean prefill on the CPU box.
    # Empty history (first message, or an older client) → the previous
    # stateless behaviour, byte-for-byte.
    depth = request.response_depth if request.response_depth in {"overview", "technical", "guided", "operational"} else "overview"
    depth_instruction = {
        "overview": "Quick mode: answer in plain language in roughly 100–220 words, with no more than four main points. Put the answer first.",
        "technical": "Technical mode: add concrete mechanisms, authentication or protocol details, detection signals, failure modes, and mitigations. Add substance instead of repeating the short answer.",
        "guided": "Guided mode: give an organized defensive or approved-lab workflow with numbered stages, prerequisites, checkpoints, expected observations, cleanup, and hardening.",
        "operational": "Lab mode: for the established approved lab, give a reproducible workflow with assumptions, placeholders, validation, rollback, cleanup, and audit points.",
    }[depth]
    user_content = request.prompt if depth == "overview" else f"RESPONSE DEPTH: {depth}. {depth_instruction}\n\n{request.prompt}"

    # Put a short style/state reminder after the user text as well as in the
    # system prompt. Small local models follow a nearby, concrete instruction
    # more reliably than a long policy block at the start of the context.
    if policy.state == "authorized_lab":
        user_content += "\n\nINTERNAL STYLE RULE: Authorization is already established. Do not ask for permission again. Give the requested steps in plain language with numbered stages and checks."
    elif policy.state == "ambiguous":
        user_content += "\n\nINTERNAL STYLE RULE: Answer the conceptual or defensive part first in plain language. Ask one scope question only if operational detail is truly necessary. Do not use a canned refusal."

    messages: list[dict] = [{"role": "system", "content": system_prompt}]
    if tier != "anon" and request.history:
        messages.extend(build_history_messages(request.history))
    messages.append({"role": "user", "content": user_content})

    analysis_headers = {
        "X-Oyster-Model": ollama_model,
        "X-Oyster-Policy-State": policy.state,
        "X-Oyster-Policy-Replaced": "true" if (policy.boundary or verification_boundary) else "false",
        "X-Oyster-Response-Depth": depth,
        "X-Oyster-Domain": policy.domain,
        "X-Oyster-Goal": policy.user_goal,
        "X-Oyster-Target": policy.target_type,
        "X-Oyster-Authorization": policy.authorization_status,
        "X-Oyster-Capability": policy.requested_capability,
        "X-Oyster-Operational-Detail": policy.operational_detail,
    }

    # Refuse rather than enrol someone in a wait we know is unreasonable. The
    # cap is derived from CHAT_MAX_QUEUE_WAIT_S, so this fires on genuine
    # overload, not at an arbitrary count.
    if chat_queue.queue.is_full():
        raise HTTPException(
            status_code=503,
            detail="chat_busy",
            headers={"Retry-After": str(max(30, chat_queue.queue.eta_seconds_for_new()))},
        )

    # "Priority access to Oyster" is sold by VoiceIQ, on VoiceIQ's plans, out of
    # a database this app cannot see — so we ask, briefly, and take "no" for an
    # answer whenever the billing API is slow, down or simply not configured.
    # Resolved BEFORE submit because a job's lane is fixed when it joins the
    # line, and AFTER the is_full() check so a request we are about to refuse
    # never pays for the lookup. See services/entitlements.py.
    priority = await entitlements.is_priority(identity, bearer)

    async def run(job: chat_queue.ChatJob) -> None:
        """Runs once a slot frees. Everything expensive lives here, so the
        wait costs nothing but a queue entry."""
        if tier == "anon":
            # The real enforcement, atomic, at the moment we commit to work.
            # Off the loop: this runs inside the job's task, alongside every
            # other stream's heartbeats.
            used = await run_in_threadpool(chat_quota.consume, identity["ip"])
            if used > config.ANON_CHAT_DAILY_LIMIT:
                job.status = chat_queue.ERROR
                job.error = "anon_daily_limit"
                return
        if policy.boundary or verification_boundary:
            job.text = policy.boundary or verification_boundary or ""
            job.touch()
            return
        async for token in ollama_service.stream_chat(messages, ollama_model):
            job.text += token
            if _TRANSCRIPT_LEAK_RE.search(job.text):
                job.text = _truncate_at_leaked_turn(job.text)
                job.touch()
                break
            job.touch()

    try:
        job = chat_queue.queue.submit(_owner_key(identity), run, priority=priority)
    except chat_queue.TooManyForOwner as busy:
        # One generation per account (config.CHAT_MAX_PER_USER). Tell them what
        # they are waiting on and roughly how long, so it reads as "your other
        # message is still coming" rather than a failure.
        left = chat_queue.queue.eta_seconds(busy.existing.id)
        raise HTTPException(
            status_code=429,
            detail="chat_one_at_a_time",
            # X-Oyster-Job names the generation that is in the way, so the
            # client can re-attach to it or cancel it rather than guess. It
            # is the caller's own job — _owner_key matched — so no other
            # account's id is ever disclosed here. Exposed to the browser via
            # CORSMiddleware(expose_headers=…) in main.py.
            headers={"Retry-After": str(max(1, left or 5)),
                     "X-Oyster-Job": busy.existing.id},
        )

    # Content negotiation, deliberately: only a client that ASKS for frames
    # gets them. Anything else keeps the exact raw-text contract it has today,
    # so deploying this backend cannot break a frontend that hasn't shipped yet.
    if "application/x-ndjson" in (http_request.headers.get("accept") or ""):
        return StreamingResponse(
            _ndjson_view(job), media_type="application/x-ndjson",
            headers=analysis_headers,
        )
    return StreamingResponse(
        _raw_view(job), media_type="text/plain",
        headers=analysis_headers,
    )


@router.get("/chat/jobs/{job_id}")
async def get_chat_job(job_id: str, identity: dict = Depends(require_chat_access)):
    """Poll a job — status, place in line, and the answer so far."""
    return chat_queue.queue.snapshot(_owned_job(job_id, identity))


@router.get("/chat/jobs/{job_id}/stream")
async def stream_chat_job(job_id: str, identity: dict = Depends(require_chat_access)):
    """Re-attach to a job after a refresh. Same frames as POST /chat."""
    return StreamingResponse(
        _ndjson_view(_owned_job(job_id, identity)),
        media_type="application/x-ndjson",
    )


@router.post("/chat/jobs/{job_id}/cancel")
async def cancel_chat_job(job_id: str, identity: dict = Depends(require_chat_access)):
    """Stop a generation — the Stop button, and the frontend's way out of
    `chat_one_at_a_time` when the job in the way is one it has lost track of.

    Owner-only through ``_owned_job`` (404 for anyone else's job, never 403).
    Idempotent: cancelling a finished job returns its final snapshot and
    changes nothing. Any open stream of this job ends with the ``cancelled``
    error frame; the slot is released as the task unwinds, so the same
    account may submit again immediately. Stays ``async def`` because
    ``cancel`` must run on the event loop (see ChatQueue.cancel).
    """
    job = _owned_job(job_id, identity)
    chat_queue.queue.cancel(job, chat_queue.CANCEL_BY_OWNER)
    return chat_queue.queue.snapshot(job)
