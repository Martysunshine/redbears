from __future__ import annotations

from fastapi import APIRouter, HTTPException

import log_config
from models.schemas import Citation, SecurityChatRequest
from prompt_utils import disclaimer_instruction, load_prompt
from services import ollama_service, project_service, rag_service, scope_service
from services.user_memory import service as memory_service

router = APIRouter(tags=["rag"])


@router.post("/rag/security-chat")
async def rag_security_chat(request: SecurityChatRequest):
    scope_active = scope_service.is_scope_active()

    # Guidance is never scope-gated — only REAL tool execution (via the Execution
    # Engine) is. An out-of-scope target does NOT get a bare refusal; it gets the
    # full methodology + a local-lab reproduction + the scope info needed to run
    # it for real. The scope violation is still audited.
    target_authorized = True
    scope_reason = ""
    if request.target:
        target_authorized, scope_reason = scope_service.validate_target(request.target)
        if not target_authorized:
            log_config.audit(
                "scope_violation",
                {"target": request.target, "reason": scope_reason, "action": "reframed_to_methodology"},
            )
        else:
            log_config.audit("security_chat", {"target": request.target, "prompt": request.prompt[:200]})
    else:
        log_config.audit("security_chat", {"target": "none", "prompt": request.prompt[:200]})

    system_prompt = load_prompt("redteam_system_prompt.txt")
    footer = disclaimer_instruction()
    if footer:
        system_prompt = f"{system_prompt}\n\n{footer}"

    project_id = project_service.get_active_project_id()
    mem_block = memory_service.format_memory_context(
        await memory_service.retrieve_relevant(project_id, request.prompt)
    )
    if mem_block:
        system_prompt = f"{system_prompt}\n\n---\n\n{mem_block}"

    citations_raw = await rag_service.search_async(request.prompt, top_k=request.top_k)

    if request.target and not target_authorized:
        target_line = (
            f"TARGET: {request.target} — NOT in the authorized engagement scope "
            f"({scope_reason}).\n"
            "Because this target is not authorized for REAL execution, do NOT imply any tool "
            "was run against it. Instead give: (1) the full assessment methodology and exact "
            "tools/commands, (2) a local-lab reproduction the operator can practice on safely, "
            "(3) detection + remediation, and (4) the exact scope fields to set (domains/URLs/"
            "IPs/CIDRs/window/authorization ref) before running any tool for real.\n"
        )
    else:
        target_line = f"TARGET: {request.target}\n" if request.target else ""

    if citations_raw:
        parts = [
            f"[{i}] From '{c['document']}':\n{c['chunk']}"
            for i, c in enumerate(citations_raw, 1)
        ]
        context = "\n\n".join(parts)
        prompt = (
            f"{system_prompt}\n\n"
            f"KNOWLEDGE BASE CONTEXT:\n{context}\n\n"
            f"{target_line}"
            f"QUESTION: {request.prompt}\n\n"
            f"Answer using the context above and your security expertise."
        )
    else:
        prompt = (
            f"{system_prompt}\n\n"
            f"{target_line}"
            f"QUESTION: {request.prompt}\n\n"
            f"Note: No relevant documents found in the knowledge base. "
            f"Answering from general security knowledge only."
        )

    answer = await ollama_service.generate(prompt, request.model)

    return {
        "answer": answer,
        "citations": [Citation(**c) for c in citations_raw],
        "model": request.model,
        "documents_queried": len({c["document"] for c in citations_raw}),
        "scope_active": scope_active,
        "target": request.target or None,
        "target_authorized": target_authorized,
        "scope_status": "in_scope" if target_authorized else "out_of_scope_reframed",
    }
