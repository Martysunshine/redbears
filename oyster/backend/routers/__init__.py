"""API routers for the Oyster backend.

Each module owns a cohesive slice of the HTTP surface that previously lived in
the monolithic ``main.py``. Paths, request/response shapes and behaviour are
unchanged — only the file layout differs.
"""

from . import (artifacts, chat, conversations, datasets, documents, evaluation,
               execution, findings, health, knowledge, profile, projects, rag,
               redteam, scope, settings, shared, system, training, user_findings,
               user_memory, vulnerabilities)

# Reachable with no authentication at all. Keep this to routes that leak
# nothing and cost nothing — anything a stranger can make the box DO belongs
# in TIERED_ROUTERS, where at least the caller is identified and charged.
PUBLIC_ROUTERS = [
    # Deploy healthchecks (UptimeRobot, docker healthcheck, Caddy).
    health.router,
    # Read-only public view of a finding the owner explicitly shared, by
    # unguessable token. No listing, no owner/project fields — see
    # routers/shared.py. This is the only unauthenticated DATA route.
    shared.router,
]

# The public chat surface (/chat, /me) — mounted in main.py WITHOUT the admin
# gate; its routes carry require_chat_access in their own signatures (the
# dependency's return value is needed by the handlers, and router-level
# dependencies discard results). Tiering: anon 1/day, signed-in unlimited,
# admin full. See routers/chat.py.
TIERED_ROUTERS = [
    chat.router,
    # Chat history for signed-in accounts. Its own routes enforce per-user
    # ownership on every operation and reject anonymous callers (401) —
    # see routers/conversations.py.
    conversations.router,
    # Attachments (file/image/video/note + summarize + RAG-ask). PUBLIC as a
    # product decision — anonymous visitors included — but tier-gated, not
    # unauthenticated: it briefly sat in PUBLIC_ROUTERS, which let anyone on
    # the internet list, read, overwrite and DELETE any project's artifacts by
    # guessing the id in the URL ("default" guesses fine), and run unlimited
    # OCR/vision/Whisper jobs on a 2-core box. Every route now takes its
    # project from services/artifact_scope.py — derived from the caller's
    # identity, never from the path — plus a per-tier daily upload quota.
    artifacts.router,
]

# The operator WORKSPACE surface — open to every signed-in account, anonymous
# refused (require_account). These used to be admin-only, which meant a
# signed-in user saw a stripped-down app while the two operator accounts saw
# the real one. What replaced the allow-list is not a weaker check but a
# different KIND of check: every route here resolves its project through
# services/project_context.py, so an account's scope, memories, settings and
# conversations live in its own workspace and cross-account access is
# unreachable rather than merely forbidden.
#
# A router belongs here only if all of its state is project-scoped. The ones
# below in PROTECTED_ROUTERS are not — they write shared, instance-wide state.
ACCOUNT_ROUTERS = [
    projects.router,
    scope.router,
    redteam.router,
    user_memory.router,
    settings.router,
    # The caller's public nickname (used as the author label on the findings
    # feed) — no email ever leaves this surface.
    profile.router,
    # Per-user saved findings (CRUD + share/revoke). Every route is
    # ownership-gated; project-scoped state only. The read-only public view
    # lives separately in shared.router (PUBLIC_ROUTERS).
    user_findings.router,
]

# Everything else stays behind services.auth_service.require_admin. Not an
# oversight — each of these either mutates state shared by the whole instance
# or executes something:
#   system      — /tools/call and /agent/run dispatch real tools
#   documents   — the operators' shared document store, which rag.py searches
#   rag         — searches that same global collection (a user's answer would
#                 quote the operators' engagement material back at them)
#   knowledge   — install/enable/rebuild reconfigure ONE knowledge base for
#                 everyone
#   datasets    — same, one shared index
#   evaluation  — runs against that shared knowledge base
#   findings    — appends to a single global data/evidence.json
#   training    — globally disabled; adapters are instance-wide
#   execution   — live tool execution. Also behind the kill-switch
#                 (OYSTER_EXECUTION_ENGINE_ENABLED); deliberately NOT opened to
#                 accounts, so flipping that switch back on never silently
#                 hands network tooling to every signup.
PROTECTED_ROUTERS = [
    system.router,
    documents.router,
    rag.router,
    knowledge.router,
    # Structured vulnerability knowledge (CISA KEV / NVD / EPSS / CWE / CAPEC) —
    # same tier as knowledge.router for the same reason: it reconfigures one
    # shared knowledge base for everyone, not a per-account resource.
    vulnerabilities.router,
    datasets.router,
    findings.router,
    execution.router,
    evaluation.router,
    training.router,
]

ALL_ROUTERS = PUBLIC_ROUTERS + TIERED_ROUTERS + ACCOUNT_ROUTERS + PROTECTED_ROUTERS
