from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Phase 1 — plain chat
# ---------------------------------------------------------------------------

class ChatMessage(BaseModel):
    """One prior turn, sent by the client so a follow-up has context.

    This is the caller's OWN conversation echoed back — no cross-account data —
    and the router trims it to a char/turn budget before use (num_ctx is small).
    content is capped well above any real turn (num_ctx is 4096 tokens total)
    so a single oversized entry cannot itself become a resource-exhaustion
    vector on an endpoint anonymous visitors can reach.
    """
    role: str  # "user" | "assistant"
    content: str = Field(max_length=20_000)


class ChatRequest(BaseModel):
    prompt: str
    model: str = "oyster-dolphin-v2"
    response_depth: str = "overview"
    system_prompt: str = ""
    agent_mode: str = "chat"
    # Prior turns for follow-up context (signed-in only; anonymous stays
    # historyless). Empty for the first message or an older client — the router
    # falls back to the previous stateless behaviour when this is empty.
    # Capped well above CHAT_HISTORY_MAX_TURNS (config.py, default 12): the
    # router's own trimming is the authoritative budget, this is only a
    # backstop against a client sending an absurdly large list to an
    # anonymously-reachable endpoint before that trimming ever runs.
    history: list[ChatMessage] = Field(default_factory=list, max_length=200)
    # Advisory only (audit/telemetry); `history` is the authoritative context.
    conversation_id: str | None = None


# ---------------------------------------------------------------------------
# Phase 2 — RAG knowledge base
# ---------------------------------------------------------------------------

class Citation(BaseModel):
    document: str
    chunk: str
    score: float


# ---------------------------------------------------------------------------
# Knowledge Packs — curated, global, source-attributed knowledge
# ---------------------------------------------------------------------------

class KnowledgeAskRequest(BaseModel):
    question: str
    model: str = "oyster-dolphin-v2"
    top_k: int = 6
    pack_id: str | None = None  # restrict to one pack, else all enabled
    filters: dict | None = None  # {domain, risk_level, publisher}
    # Prior turns of this conversation so a Knowledge-pack follow-up ("how do I
    # detect that?") keeps its subject — mirrors ArtifactAskRequest.history.
    # Retrieval still keys on `question`; history only enters generation.
    history: list = []
    # Rerank the retrieved evidence with Nemotron before answering (falls back
    # to the existing retrieval order, visibly, if the reranker is unavailable).
    rerank: bool = False


class SecurityIntelligenceAskRequest(BaseModel):
    question: str
    model: str | None = "dolphin-llama3"
    top_k: int = 8


class KnowledgeSearchRequest(BaseModel):
    query: str
    top_k: int = 8
    pack_id: str | None = None
    filters: dict | None = None


class KnowledgeEnableRequest(BaseModel):
    enabled: bool


class VulnSearchRequest(BaseModel):
    query: str
    top_k: int = 8
    kev_only: bool = False
    min_cvss: float | None = None
    min_epss: float | None = None
    since: str | None = None  # ISO date; filters on last_modified_date


class KnowledgeRiskRequest(BaseModel):
    text: str


class RAGChatResponse(BaseModel):
    answer: str
    citations: list[Citation]
    model: str
    documents_queried: int


# ---------------------------------------------------------------------------
# Phase 3 — Red-team scope and workflows
# ---------------------------------------------------------------------------

class ScopeSetRequest(BaseModel):
    # Phase 4 format
    project: str = ""
    allowed_targets: list[str] = []
    blocked_targets: list[str] = []
    allowed_tests: list[str] = []
    # Legacy Phase 3 fields kept for compatibility
    engagement_name: str = ""
    authorized_by: str = ""
    start_date: str = ""
    end_date: str = ""
    domains: list[str] = []
    ip_ranges: list[str] = []
    repositories: list[str] = []
    notes: str = ""


class RedTeamPlanRequest(BaseModel):
    target: str
    objective: str
    methodology: str = ""
    model: str = "dolphin-llama3"


class CodeReviewRequest(BaseModel):
    target_repo: str
    code_snippet: str = ""
    language: str = ""
    focus: str = ""
    model: str = "dolphin-llama3"


class FindingsReportRequest(BaseModel):
    engagement_name: str
    findings: list[dict]
    model: str = "dolphin-llama3"


class SecurityChatRequest(BaseModel):
    prompt: str
    target: str = ""
    model: str = "dolphin-llama3"
    top_k: int = 4


# ---------------------------------------------------------------------------
# Phase 4 — document search and summarize
# ---------------------------------------------------------------------------

class DocumentSearchRequest(BaseModel):
    query: str
    top_k: int = 5


# ---------------------------------------------------------------------------
# Phase 4 — Red Team UI
# ---------------------------------------------------------------------------

class ReconRequest(BaseModel):
    target: str
    description: str = ""
    model: str = "deepseek-r1"


class EvidenceLogRequest(BaseModel):
    severity: str  # critical | high | medium | low | info
    title: str
    endpoint: str
    method: str = "GET"
    steps_to_reproduce: str = ""
    screenshot_notes: str = ""
    recommended_fix: str = ""


class FixRequest(BaseModel):
    title: str
    endpoint: str
    description: str
    steps: str = ""
    stack: str = ""
    model: str = "deepseek-r1"


# ---------------------------------------------------------------------------
# Phase 5 — MCP-style tool server
# ---------------------------------------------------------------------------

class ToolCallRequest(BaseModel):
    tool: str
    arguments: dict = {}


class AgentRunRequest(BaseModel):
    task: str
    model: str = "dolphin3"


# ---------------------------------------------------------------------------
# Local Alpha — Project System (the aggregate root)
# ---------------------------------------------------------------------------

class ProjectCreateRequest(BaseModel):
    name: str
    description: str = ""
    scope: dict = {}
    activate: bool = True


class ProjectUpdateRequest(BaseModel):
    name: str | None = None
    description: str | None = None
    status: str | None = None


class ProjectScopeRequest(BaseModel):
    scope: dict


# ---------------------------------------------------------------------------
# Local Alpha — Conversation persistence (sidebar history)
# ---------------------------------------------------------------------------

class ConversationCreateRequest(BaseModel):
    mode: str = "basic"
    title: str = "New Chat"


class ConversationRenameRequest(BaseModel):
    title: str | None = None
    pinned: bool | None = None


class ConversationMessageRequest(BaseModel):
    role: str  # user | assistant
    content: str
    citations: list = []
    documents_queried: int | None = None


class MessageFeedbackRequest(BaseModel):
    """Was this answer any good, and what should it have said?

    ``rating=None`` clears an existing vote (clicking an active thumb again).
    ``correction`` is optional but is the valuable half: a thumbs-down only
    excludes a bad answer from training, whereas a correction replaces it as the
    training target and is recalled on the next message.
    """
    rating: str | None = None  # "up" | "down" | None to clear
    correction: str = ""


# ---------------------------------------------------------------------------
# Findings (per-user saved chat messages)
# ---------------------------------------------------------------------------

# NB: named UserFinding* on purpose. `FindingCreateRequest` is already taken
# further down this file by the Execution Engine (title REQUIRED, severity,
# evidence_ids). Python does not complain about a duplicate class name — the
# later definition simply wins — so an earlier version of these models was
# silently shadowed and every POST /findings 422'd on a "missing title".
class UserFindingCreateRequest(BaseModel):
    content: str
    title: str | None = None
    conversation_id: str | None = None
    conv_mode: str | None = None
    message_id: str | None = None
    citations: list = []
    in_report: bool = False
    # Pentest fields (absorbed from the red-team Evidence logger). Empty for a
    # finding captured from chat; filled in when one is logged by hand.
    severity: str | None = None
    endpoint: str = ""
    method: str = ""
    notes: str = ""
    recommended_fix: str = ""
    # affected_asset is a general target identifier (host, IP, service, device)
    # — distinct from endpoint/method, which are HTTP-specific and don't fit a
    # network host, a mobile app, or a piece of hardware. unresolved_questions
    # lets a finding honestly record what the assessment did NOT establish
    # (e.g. root cause unconfirmed, scope of exposure unknown) instead of the
    # export silently implying the investigation was complete.
    affected_asset: str = ""
    unresolved_questions: str = ""


class UserFindingUpdateRequest(BaseModel):
    title: str | None = None
    content: str | None = None
    in_report: bool | None = None
    severity: str | None = None
    endpoint: str | None = None
    method: str | None = None
    notes: str | None = None
    recommended_fix: str | None = None
    affected_asset: str | None = None
    unresolved_questions: str | None = None


# ---------------------------------------------------------------------------
# Artifacts (project-scoped uploads)
# ---------------------------------------------------------------------------

class NoteCreateRequest(BaseModel):
    title: str = ""
    content: str
    conversation_id: str | None = None


class ArtifactSummarizeRequest(BaseModel):
    # Artifact analysis must use the same verified Oyster default as chat;
    # silently selecting a legacy Dolphin tag made the workflow impossible to
    # reproduce from the active-model health report.
    model: str = "oyster-dolphin-v2"


class ArtifactAskRequest(BaseModel):
    question: str
    model: str = "oyster-dolphin-v2"
    top_k: int = 5
    # Prior turns of this conversation, so a RAG follow-up ("summarize that",
    # "and the third one?") is understood in context. Retrieval still keys on
    # `question` (unchanged); history is only added to the generation prompt.
    # Capped for the same reason as ChatRequest.history above — this endpoint
    # is reachable by anonymous visitors on their own auto-provisioned project.
    history: list[ChatMessage] = Field(default_factory=list, max_length=200)


# ---------------------------------------------------------------------------
# Execution Engine (authorization-aware tool execution)
# ---------------------------------------------------------------------------

class ProposalCreateRequest(BaseModel):
    tool_id: str
    action_id: str
    targets: list[str] = []
    parameters: dict = {}
    objective: str = ""
    conversation_id: str | None = None
    project_id: str | None = None


class ApprovalRequest(BaseModel):
    note: str = ""
    approved_by: str = "local-user"


class RejectRequest(BaseModel):
    note: str = ""


class EvidenceCreateRequest(BaseModel):
    title: str
    observation: str


class FindingCreateRequest(BaseModel):
    title: str
    severity: str = "info"
    summary: str = ""
    evidence_ids: list[str] = []
    recommendation: str = ""


class CleanupRequest(BaseModel):
    detail: str = ""


class ToolEnableRequest(BaseModel):
    enabled: bool


# ---------------------------------------------------------------------------
# User Memory (long-term, per-project, encrypted-at-rest)
# ---------------------------------------------------------------------------

class MemoryAddRequest(BaseModel):
    type: str
    subject: str
    content: str
    confidence: float = 0.9


class MemoryUpdateRequest(BaseModel):
    content: str | None = None
    subject: str | None = None
    type: str | None = None


class MemorySettingsRequest(BaseModel):
    memory_enabled: bool | None = None
    auto_save: bool | None = None
    ask_before_saving: bool | None = None


class MemorySearchRequest(BaseModel):
    query: str
    top_k: int = 5


class ConflictResolveRequest(BaseModel):
    keep_id: str


# ---------------------------------------------------------------------------
# Dataset RAG (approved, licence-gated cybersecurity datasets)
# ---------------------------------------------------------------------------

class DatasetSearchRequest(BaseModel):
    query: str
    top_k: int = 6
    dataset_ids: list[str] | None = None


class DatasetAskRequest(BaseModel):
    question: str
    model: str = "dolphin3"
    top_k: int = 6
    dataset_ids: list[str] | None = None


# ---------------------------------------------------------------------------
# Training pipeline (disabled by default, consent-gated, LoRA)
# ---------------------------------------------------------------------------

class TrainingConsentRequest(BaseModel):
    allow: bool


class TrainingDatasetBuildRequest(BaseModel):
    notes: str = ""


class TrainingJobRequest(BaseModel):
    dataset_version: str
    base_model: str | None = None
    epochs: int = 3
    learning_rate: float = 2e-4


class AdapterApproveRequest(BaseModel):
    notes: str = ""
