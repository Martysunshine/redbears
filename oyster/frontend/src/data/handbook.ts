// The in-app "Oyster Company Handbook" content.
//
// Kept as DATA (not one giant JSX component) so it stays maintainable: add or
// edit an article here and the panel renders it, search indexes it, and the
// context-aware ordering picks it up — no component changes needed. Every claim
// here must match how Oyster actually behaves; this is user-facing help, not
// marketing. No external links, no analytics, no fake features.

export type HandbookContext =
  | "chat"
  | "rag"
  | "redteam"
  | "blueteam"
  | "intel"
  | "findings"
  | "general";

export type HandbookBlock =
  | { type: "p"; text: string }
  | { type: "h"; text: string }
  | { type: "ul"; items: string[] }
  | { type: "steps"; items: string[] }
  | { type: "callout"; tone: "info" | "warn" | "safety"; text: string }
  | { type: "prompts"; items: string[] };

export interface HandbookArticle {
  id: string;
  title: string;
  /** Modes that should surface this article first. */
  context: HandbookContext[];
  body: HandbookBlock[];
}

export interface HandbookSection {
  id: string;
  title: string;
  articles: HandbookArticle[];
}

export interface GlossaryEntry {
  term: string;
  def: string;
}

// Map a workspace mode to the handbook context it should prioritise.
export function modeToHandbookContext(mode: string): HandbookContext {
  if (mode === "rag") return "rag";
  if (["scope", "recon", "testplan", "fix", "codelab", "execute"].includes(mode)) return "redteam";
  if (["soccopilot", "cookbook", "notes", "shield"].includes(mode)) return "blueteam";
  if (mode === "intel") return "intel";
  if (mode === "findings") return "findings";
  return "chat";
}

export const HANDBOOK: HandbookSection[] = [
  {
    id: "getting-started",
    title: "Getting started",
    articles: [
      {
        id: "what-is-oyster",
        title: "What Oyster is",
        context: ["chat", "general"],
        body: [
          { type: "p", text: "Oyster is a security-focused AI assistant from Red Orca. You chat with it about offensive and defensive security, upload your own documents so it can answer from them, and — for authorized operators — run a small set of real security tools behind human approval." },
          { type: "p", text: "It is built for security teams: penetration testers, SOC analysts, and engineers who need fast, evidence-backed answers about vulnerabilities, hardening, detection, and response." },
          { type: "h", text: "What it does well" },
          { type: "ul", items: [
            "Answers security questions with citations to real sources, not just opinion.",
            "Reads your uploaded files (PDFs, docs, notes, images, video) and answers from them.",
            "Investigates CVEs and maps attacker techniques (MITRE ATT&CK) with references.",
            "Helps scope, plan, and report on authorized assessments.",
          ] },
          { type: "h", text: "What it will not do" },
          { type: "ul", items: [
            "Attack systems on its own — real tool runs always require explicit human approval.",
            "Invent sources or CVEs. If it lacks evidence, it says so rather than guessing.",
            "Act against targets you have not been authorized to test.",
          ] },
        ],
      },
      {
        id: "who-its-for",
        title: "Who it is for & what it solves",
        context: ["general"],
        body: [
          { type: "p", text: "Oyster is designed for the people who do security work day to day, and the companies that employ them." },
          { type: "ul", items: [
            "Red teams / pentesters: scoping, methodology, PoCs, and report writing for authorized engagements.",
            "Blue teams / SOC analysts: CVE triage, detection engineering, log and IOC investigation, and response planning.",
            "Engineers & leads: understanding a finding, hardening a service, or reviewing code for security issues.",
          ] },
          { type: "p", text: "The problem it solves: security knowledge is scattered across standards, advisories, and tribal experience. Oyster puts a grounded, source-cited assistant next to your own documents so answers are specific to your context and traceable to a source." },
        ],
      },
      {
        id: "evidence-and-citations",
        title: "How evidence-based answers & citations work",
        context: ["chat", "rag", "intel", "general"],
        body: [
          { type: "p", text: "For knowledge and file questions, Oyster retrieves relevant passages first, then answers from them and shows the sources it used. A citation is not decoration — it is the passage the answer was built on." },
          { type: "ul", items: [
            "Click a citation to see the exact passage, its source, publisher, and (where available) a link.",
            "A 'knowledge' citation comes from Oyster's curated security knowledge; a 'project'/'uploaded' citation comes from a file you added.",
            "If the sources do not support a claim, treat the claim with caution — the citation is your check.",
          ] },
          { type: "callout", tone: "info", text: "Verify, don't just trust: read the cited passage before you act on a high-stakes answer. If there is no citation and the answer states a specific fact, ask Oyster for its source." },
        ],
      },
      {
        id: "approvals-and-safety",
        title: "How approvals & safety controls work",
        context: ["redteam", "general"],
        body: [
          { type: "p", text: "Oyster can discuss any technique and write proof-of-concept code. What it cannot do is silently run an intrusive action. Real tool execution goes through a deterministic Execution Engine that sits outside the model." },
          { type: "steps", items: [
            "The model proposes an action (e.g. a scan).",
            "The engine classifies its risk and checks it against your authorized scope.",
            "Low-risk, read-only actions may run; anything intrusive requires explicit human approval.",
            "Destructive actions are blocked by default — the model can never approve or run them on its own.",
            "Every run is scope-validated, audited, and evidence-backed.",
          ] },
          { type: "callout", tone: "safety", text: "The safety boundary is the Execution Engine, not the model refusing to talk. Discussing methodology is always allowed; running it against a real target is gated." },
        ],
      },
      {
        id: "data-protection",
        title: "How your company data is protected",
        context: ["general"],
        body: [
          { type: "ul", items: [
            "Each account works in its own project workspace — your conversations, files, and findings are scoped to you and not shared with other accounts.",
            "Uploaded documents are indexed into an isolated store; Oyster's curated knowledge and your files never bleed into each other's results.",
            "Long-term memory (facts Oyster remembers about your work) is per-project, encrypted at rest, and fully manageable — you can review, edit, or delete it in Settings.",
            "Secrets that appear in files or tool output are redacted from previews, the index, and logs.",
          ] },
          { type: "callout", tone: "info", text: "You control your data: 'Delete all personal data' in Settings erases your memories, and deleting a conversation or file removes it." },
        ],
      },
      {
        id: "projects",
        title: "How to create a project",
        context: ["general", "chat"],
        body: [
          { type: "p", text: "A project (engagement) is the container for a body of work — its conversations, uploaded files, scope, and findings all live together." },
          { type: "steps", items: [
            "Open the project switcher at the top of the sidebar.",
            "Choose 'New project' and give it a name.",
            "It becomes active immediately; new chats and uploads land in it.",
            "Switch projects any time from the same menu; rename or delete from the row's actions.",
          ] },
        ],
      },
      {
        id: "documents",
        title: "How to upload & organize documents",
        context: ["rag", "general"],
        body: [
          { type: "p", text: "Use the + button in the composer to add material to the active project." },
          { type: "ul", items: [
            "Upload Files: PDFs, Word docs, and text/code files.",
            "Upload Folder: a whole directory, structure preserved.",
            "Upload Image / Video: analyzed locally (text extraction, description, transcript).",
            "Create Note: type text straight into the knowledge base.",
            "Import Knowledge Pack: add a curated, source-attributed security pack.",
          ] },
          { type: "p", text: "Each item shows a status chip while it processes; once 'ready' it is searchable. Remove an item with its × , or summarize it with the sparkle icon." },
        ],
      },
      {
        id: "manage-conversations",
        title: "Start, rename, edit, continue & delete chats",
        context: ["chat", "rag"],
        body: [
          { type: "ul", items: [
            "Start: click 'New Chat' — a fresh, blank chat opens immediately (a new load always opens a clean chat, not your last one).",
            "Continue: pick any chat from History; it loads its messages and you can keep going with full context of the conversation.",
            "Rename: use the ⋯ menu on a history row → Rename (or pin it to keep it at the top).",
            "Edit a message: hover your own message and choose Edit — it resends with your change and regenerates the replies below it.",
            "Delete: ⋯ menu → Delete. Deleting the open chat opens a fresh one; other chats are untouched.",
          ] },
          { type: "callout", tone: "info", text: "A brand-new chat is a draft — it is only saved once you send the first message, so empty chats never clutter your history." },
        ],
      },
      {
        id: "verify-an-answer",
        title: "How to verify an answer instead of trusting it",
        context: ["chat", "rag", "intel", "general"],
        body: [
          { type: "steps", items: [
            "Check for citations and open at least one — does the passage actually support the claim?",
            "For a CVE or version claim, confirm the identifier and affected range against the cited advisory.",
            "Ask a follow-up: 'What is your source for that?' or 'Show the exact text you used.'",
            "For anything you will act on, treat Oyster as a fast first pass, not the final word — reproduce it in a lab or confirm against the authoritative source.",
          ] },
          { type: "callout", tone: "info", text: "Rate answers with 👍/👎. A thumbs-down with a correction teaches Oyster what the answer should have been and is recalled on your next message." },
        ],
      },
    ],
  },
  {
    id: "red-team",
    title: "Red Team guide",
    articles: [
      {
        id: "authorized-scope",
        title: "Authorized targets only — read first",
        context: ["redteam"],
        body: [
          { type: "callout", tone: "safety", text: "Only test systems you own or have explicit, written authorization to assess. Testing anything else is likely illegal and is never something Oyster will run for you." },
          { type: "p", text: "Oyster will freely explain technique, tools, and proof-of-concept code for learning and authorized work. Running a real action against a live target is separate and gated: it must fall inside an authorized scope and pass the approval controls." },
        ],
      },
      {
        id: "what-red-team-is",
        title: "What Red Team testing is & when to use it",
        context: ["redteam"],
        body: [
          { type: "p", text: "Red teaming is authorized, goal-driven simulation of a real attacker to find exploitable weaknesses before someone hostile does. Use it when you have permission to assess a system and want to know how it would actually fail." },
          { type: "h", text: "What Oyster's Red Team helps with" },
          { type: "ul", items: [
            "Scope: defining and recording exactly what you are allowed to touch.",
            "Recon & planning: turning an objective into a structured, methodology-backed test plan.",
            "Fix Advisor: turning a finding into concrete remediation.",
            "Code Lab: reviewing code for security issues.",
            "Execute (operators): running a small set of read-only/low-risk tools behind approval.",
          ] },
        ],
      },
      {
        id: "define-scope",
        title: "How to define an authorized scope",
        context: ["redteam"],
        body: [
          { type: "steps", items: [
            "Open Scope in the Red Team menu.",
            "Add the domains, IP ranges, and repositories you are authorized to assess.",
            "Add any explicitly out-of-scope targets and the allowed test types.",
            "Save. Scope-gated actions now check against this, and out-of-scope targets are refused (and logged).",
          ] },
          { type: "callout", tone: "warn", text: "Scope is the contract. If a target is not in scope, Oyster will give you methodology and a lab-reproduction path instead of a live-attack plan." },
        ],
      },
      {
        id: "begin-assessment",
        title: "How to begin a safe assessment",
        context: ["redteam"],
        body: [
          { type: "steps", items: [
            "Set scope first.",
            "Use Recon / Planner to produce a structured plan for your objective.",
            "Work through it, capturing evidence as you go (save answers to Findings).",
            "Only run real tools via Execute, and only after reviewing the proposed action and approving it.",
          ] },
        ],
      },
      {
        id: "interpret-findings",
        title: "Reading findings, severity, evidence & remediation",
        context: ["redteam", "findings"],
        body: [
          { type: "ul", items: [
            "Severity reflects impact × exploitability — treat it as a prioritization aid, not an absolute.",
            "Evidence is what makes a finding credible: the request/response, output, or citation behind it.",
            "Remediation should be specific and testable — Fix Advisor turns a finding into concrete steps.",
            "A finding without evidence is a hypothesis; capture the proof before you report it.",
          ] },
        ],
      },
      {
        id: "never-auto",
        title: "What needs approval & what Oyster never auto-runs",
        context: ["redteam"],
        body: [
          { type: "ul", items: [
            "Read-only local analysis may run without approval.",
            "Low-impact active checks require explicit approval each time.",
            "Intrusive actions require deliberate, explicit human approval.",
            "Destructive actions are blocked by default and never run automatically.",
          ] },
          { type: "callout", tone: "safety", text: "The model can propose an action but can never approve or execute it. Approval is always a human decision." },
        ],
      },
      {
        id: "useful-report",
        title: "How to produce a useful report",
        context: ["redteam", "findings"],
        body: [
          { type: "steps", items: [
            "Capture findings from chat as you work (Create Finding / Add to Report).",
            "Give each a clear title, severity, affected endpoint, and evidence.",
            "Use Fix Advisor to attach concrete remediation.",
            "Curate the report subset (Add to Report) so it tells a clean story: what, impact, proof, fix.",
          ] },
        ],
      },
      {
        id: "red-team-prompts",
        title: "Example safe workflows & prompts",
        context: ["redteam"],
        body: [
          { type: "prompts", items: [
            "Draft a test plan for the login flow of my authorized target app.example.com, focused on auth and session handling.",
            "Review this FastAPI endpoint for security issues and show the CWE for each.",
            "I found reflected input in a search parameter on my in-scope app — how do I safely confirm XSS in a lab first?",
            "Turn this finding into a remediation with concrete code changes and a test to confirm the fix.",
          ] },
        ],
      },
    ],
  },
  {
    id: "blue-team",
    title: "Blue Team guide",
    articles: [
      {
        id: "what-blue-team-is",
        title: "What Blue Team operations are & when to use them",
        context: ["blueteam"],
        body: [
          { type: "p", text: "Blue teaming is defense: detecting, investigating, and responding to threats, and hardening systems so attacks fail. Use it for CVE triage, detection engineering, incident investigation, and response planning." },
          { type: "h", text: "What Oyster's Blue Team helps with" },
          { type: "ul", items: [
            "SOC Copilot: a case-centric analyst workbench — evidence, detections, network, timeline, IOCs, MITRE mapping, and reports.",
            "Cook Book / Notes: reusable defensive playbooks and your own working notes.",
            "Shield: copy-and-run reference for the local scanner (nothing executes inside Oyster).",
          ] },
        ],
      },
      {
        id: "cve-investigation",
        title: "How to investigate a CVE",
        context: ["blueteam", "intel"],
        body: [
          { type: "steps", items: [
            "Ask Security Intel for the CVE by its identifier (e.g. CVE-2021-44228).",
            "Read the direct answer plus severity, exploitation status, and affected systems.",
            "Check whether it is known-exploited (KEV) and its EPSS likelihood to prioritise.",
            "Confirm your installed version against the affected range, then plan detection and mitigation.",
          ] },
          { type: "callout", tone: "info", text: "Oyster will not invent a CVE. If it has no data for an identifier, it tells you so rather than guessing." },
        ],
      },
      {
        id: "logs-iocs",
        title: "Working with logs, indicators & findings",
        context: ["blueteam"],
        body: [
          { type: "ul", items: [
            "Upload real telemetry (Windows EVTX/JSON, Zeek, Suricata EVE, PCAP) to a SOC Copilot case for real analysis; plain text yields empty results, honestly.",
            "Extract IOCs, run Sigma/YARA matching, and correlate events into a timeline.",
            "Map observed behaviour to MITRE ATT&CK techniques for coverage and gaps.",
          ] },
        ],
      },
      {
        id: "confidence",
        title: "Interpreting citations & confidence",
        context: ["blueteam", "intel"],
        body: [
          { type: "ul", items: [
            "'Grounded' means the answer is backed by retrieved sources; 'partial' or 'none' means treat it with more caution.",
            "A data-gap warning tells you Oyster is missing information — it is being honest, not unhelpful.",
            "Open the sources to confirm before you build a detection or push a change.",
          ] },
        ],
      },
      {
        id: "response-plan",
        title: "Turning evidence into a response plan",
        context: ["blueteam"],
        body: [
          { type: "steps", items: [
            "Establish what happened from the evidence (timeline, affected assets, IOCs).",
            "Contain: what to isolate or block now.",
            "Eradicate & recover: remove the foothold and restore safely.",
            "Harden: the detection and configuration changes that stop a repeat, each testable.",
          ] },
        ],
      },
      {
        id: "blue-team-prompts",
        title: "Example defensive workflows & prompts",
        context: ["blueteam"],
        body: [
          { type: "prompts", items: [
            "Investigate CVE-2021-44228: severity, exploitation, affected versions, and how to detect it.",
            "Write a Sigma rule to detect PowerShell encoded-command execution and explain each condition.",
            "I have these IOCs from an alert — what ATT&CK techniques do they map to and what should I check next?",
            "Turn this incident evidence into a containment and remediation plan.",
          ] },
        ],
      },
    ],
  },
  {
    id: "rag-knowledge",
    title: "RAG & knowledge guide",
    articles: [
      {
        id: "kb-contents",
        title: "What the knowledge base contains",
        context: ["rag", "intel"],
        body: [
          { type: "p", text: "Oyster ships with a large, curated, source-attributed security knowledge base (standards, advisories, attacker techniques, and defensive references). These are searchable reference chunks — not model training data — and every answer built from them can cite its source." },
        ],
      },
      {
        id: "docs-vs-knowledge",
        title: "Your documents vs Oyster's knowledge",
        context: ["rag"],
        body: [
          { type: "ul", items: [
            "Your uploaded documents live in your project and answer questions about YOUR environment.",
            "Oyster's curated knowledge answers general security questions with authoritative references.",
            "They are stored separately and never mix in results — a project answer will not leak curated knowledge and vice-versa, unless an answer deliberately blends both and labels each.",
          ] },
        ],
      },
      {
        id: "retrieval-works",
        title: "How retrieval & citations work",
        context: ["rag", "intel"],
        body: [
          { type: "p", text: "When you ask a question, Oyster searches for the most relevant passages, ranks them, and answers from the top results — then shows those passages as citations. The answer is grounded in what was retrieved, so the citations are the evidence trail." },
        ],
      },
      {
        id: "insufficient-evidence",
        title: "What 'insufficient evidence' means",
        context: ["rag", "intel"],
        body: [
          { type: "p", text: "If retrieval finds nothing relevant, Oyster says the evidence is insufficient rather than inventing an answer. That is the system working correctly — it means you need to add a document, rephrase, or accept that the knowledge base does not cover it." },
        ],
      },
      {
        id: "improve-query",
        title: "How to improve a weak query",
        context: ["rag", "intel", "chat"],
        body: [
          { type: "ul", items: [
            "Name the specific system, technology, or file you mean.",
            "Use the real identifiers (CVE, CWE, technique id, exact endpoint).",
            "Ask one thing at a time; follow up to drill in — Oyster keeps the conversation's context.",
            "If a file should hold the answer, confirm it finished processing (status 'ready').",
          ] },
        ],
      },
      {
        id: "project-isolation",
        title: "How project isolation works & reviewing sources",
        context: ["rag", "general"],
        body: [
          { type: "p", text: "Everything you upload is scoped to the active project and to your account. Switching projects switches the documents in play. To review the source behind any answer, click its citation to open the exact passage, its origin, and (where available) a link." },
        ],
      },
    ],
  },
  {
    id: "troubleshooting",
    title: "Troubleshooting & glossary",
    articles: [
      {
        id: "no-answer",
        title: "No answer returned",
        context: ["chat", "rag", "general"],
        body: [
          { type: "ul", items: [
            "Check the status dot in the sidebar footer — if it is red, the backend is unreachable; click it/reconnect and retry.",
            "If Oyster is busy (many people chatting), it will say so and give you a place in line — wait, don't resend.",
            "On the free tier you get one message a day; sign in for unlimited.",
          ] },
        ],
      },
      {
        id: "weak-answer",
        title: "Weak or irrelevant answer",
        context: ["chat", "rag", "intel"],
        body: [
          { type: "ul", items: [
            "Add specifics and real identifiers; ask one focused question.",
            "For file questions, confirm the file is 'ready' and use RAG Analyst.",
            "Give it a 👎 with a correction — that both flags it and improves the next answer.",
            "Try a stronger model from the footer picker for harder questions (it is slower).",
          ] },
        ],
      },
      {
        id: "upload-not-processed",
        title: "Upload not processed",
        context: ["rag"],
        body: [
          { type: "ul", items: [
            "Watch the chip's status; large files and video take longer.",
            "'failed' shows the reason on hover — an unsupported or corrupt file is rejected honestly.",
            "Re-open the file to reprocess, or remove and re-add it.",
          ] },
        ],
      },
      {
        id: "conversation-wont-open",
        title: "Conversation will not open",
        context: ["chat", "rag"],
        body: [
          { type: "p", text: "If a chat fails to load you will see an error with a 'Try again' button rather than a blank screen. Retry; if it persists the conversation may have been deleted. Your other conversations are unaffected." },
        ],
      },
      {
        id: "suggestion-wont-run",
        title: "Suggested question does not run",
        context: ["chat", "rag"],
        body: [
          { type: "p", text: "Click a suggested question once — it opens/continues the chat, sends the question, and streams the answer. If nothing happens, check the backend status dot; if it is offline the send is refused until it reconnects." },
        ],
      },
      {
        id: "citation-unavailable",
        title: "Citation unavailable",
        context: ["rag", "intel"],
        body: [
          { type: "p", text: "Some sources have a passage but no public link; you can still read the retrieved text. If a citation will not expand, the underlying chunk reference may be from an older index — the answer text is still what the model used." },
        ],
      },
      {
        id: "when-new-chat",
        title: "When to start a new chat",
        context: ["chat", "rag"],
        body: [
          { type: "ul", items: [
            "When you switch to an unrelated topic — long, mixed threads dilute context and slow answers.",
            "The model has a limited context window, so a fresh chat for a new task usually gives sharper answers.",
            "Keep a focused thread per task; pin the ones you return to.",
          ] },
        ],
      },
    ],
  },
];

export const GLOSSARY: GlossaryEntry[] = [
  { term: "RAG (retrieval-augmented generation)", def: "Answering by first retrieving relevant passages, then generating from them — so answers are grounded and citable." },
  { term: "Citation", def: "The exact source passage an answer was built on. Click it to verify the claim." },
  { term: "Knowledge pack", def: "A curated, versioned, source-attributed bundle of security knowledge you can install into the knowledge base." },
  { term: "Project / engagement", def: "The workspace that holds a body of work — its chats, files, scope, and findings — scoped to your account." },
  { term: "Scope", def: "The domains, IPs, and repos you are authorized to assess. Scope-gated actions are refused outside it." },
  { term: "Finding", def: "A recorded security observation — from a chat message or logged by hand — with severity, evidence, and (ideally) a fix." },
  { term: "Execution Engine", def: "The deterministic layer outside the model that decides whether a real tool may run, with approval and audit." },
  { term: "Approval gate", def: "A required human decision before an intrusive tool action runs. The model can propose but never approve." },
  { term: "CVE", def: "Common Vulnerabilities and Exposures — a public identifier for a specific known vulnerability." },
  { term: "CWE", def: "Common Weakness Enumeration — the class of weakness a vulnerability belongs to (e.g. CWE-79 for XSS)." },
  { term: "KEV", def: "CISA's Known Exploited Vulnerabilities catalogue — vulnerabilities seen exploited in the wild; prioritise these." },
  { term: "EPSS", def: "Exploit Prediction Scoring System — an estimated probability a vulnerability will be exploited soon." },
  { term: "MITRE ATT&CK", def: "A knowledge base of real adversary tactics and techniques, each with an id like T1003." },
  { term: "Sigma", def: "A generic, vendor-neutral format for writing detection rules over log data." },
  { term: "YARA", def: "A pattern-matching format for identifying and classifying files, often malware." },
  { term: "IOC (indicator of compromise)", def: "An artefact — hash, IP, domain, path — that suggests a system was compromised." },
  { term: "IR / DFIR", def: "Incident Response / Digital Forensics and Incident Response — investigating and recovering from security incidents." },
  { term: "Insufficient evidence", def: "Oyster's honest signal that retrieval found nothing to support an answer — add context or rephrase." },
];
