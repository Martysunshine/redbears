"""Small, deterministic policy classifier for conversational chat.

This is deliberately narrower than a keyword blocklist.  It decides how much
operational detail the model may present based on target and authorization
signals, while leaving ordinary security explanations to the model.
"""
from __future__ import annotations

from dataclasses import dataclass
import re


# A named reference needs evidence before Oyster states what it does. This is
# intentionally structural rather than a list of suspicious words: it catches
# a specific identifier used as a tool/suite/flag/module, while ordinary
# cybersecurity explanations continue straight to the model.
_NAMED_REFERENCE = re.compile(
    r"(?:`([^`]+)`|\b([A-Z][A-Za-z0-9_-]{3,})\s+(?:tool|suite|framework|flag|option|module|service|appliance|subscription)\b|"
    r"\b(?:features?|capabilities|versions?|flags?|options?|syntax)\s+(?:does|of)\s+([A-Z][A-Za-z0-9_-]{3,})\b|"
    r"\b([A-Z][A-Za-z0-9_-]{3,})['’]?s?\s+(?:features?|capabilities|versions?|flags?|options?|syntax)\b|"
    r"\b(--[a-z][a-z0-9_-]+)\b|\b(CVE-\d{4}-\d{4,7})\b|"
    r"\b([A-Z][a-z]+(?:[A-Z][A-Za-z0-9]+)+|[A-Z]{2,}[A-Z][a-z]+(?:[A-Z][A-Za-z0-9]+)*)\b)")


def named_reference_subject(prompt: str) -> str | None:
    """Return a specific named tool/flag/CVE that needs evidence, if present."""
    text = prompt or ""
    # Natural-language feature questions put the product after the verb
    # ("what features does Product have"). Handle that structure before the
    # more general identifier patterns so the interrogative "What" is never
    # mistaken for the subject.
    feature_question = re.search(
        r"\b(?:what\s+)?(?:features?|capabilities|versions?|flags?|options?|syntax)\s+does\s+"
        r"([A-Z][A-Za-z0-9_-]{3,})\s+have\b",
        text,
        re.I,
    )
    if feature_question:
        return feature_question.group(1)
    # Natural-language product questions commonly put the name between the
    # copula and its noun: "What is Fingerprinty tool?"  Treat that name like
    # the existing "Fingerprinty tool" and feature-question forms so factual
    # claims still require evidence.
    copula_reference = re.search(
        r"\bwhat\s+is\s+(?:the\s+)?([A-Z][A-Za-z0-9_-]{3,})"
        r"(?:\s+[A-Za-z-]+){0,2}\s+(?:tool|suite|framework|service|module|appliance)\b",
        text,
        re.I,
    )
    if copula_reference:
        return copula_reference.group(1)
    for match in _NAMED_REFERENCE.finditer(prompt or ""):
        subject = next((part for part in match.groups() if part), "").strip()
        if subject and subject.lower() not in {"tool", "suite", "framework", "service", "what", "which"}:
            return subject
    # Claim shapes that require a source even when they contain no product
    # identifier: future-dated standards, universal/default assertions, and
    # exact live-market values are not facts the model should improvise.
    import datetime
    year = datetime.datetime.now(datetime.timezone.utc).year
    if any(int(candidate) > year for candidate in re.findall(r"\b20\d{2}\b", text)):
        return "the future-dated reference"
    if re.search(r"\b(?:built[- ]in|default)\b.*\b(?:keylogger|password|credential|module)\b", text, re.I):
        return "that default or built-in feature"
    if re.search(r"(?:\b(?:universal|every|all)\b|100%)\s+.*\b(?:exploit|firewall|router|password|tool|malware)\b", text, re.I):
        return "that universal claim"
    if re.search(r"\bexact\b.*\b(?:price|market|today|current)\b", text, re.I):
        return "that current market claim"
    return None


# A question that ASKS for a specific security identifier (CVE/CWE/CAPEC) by
# the vulnerability's colloquial NAME — "What is the CVE identifier of
# Log4Shell?" — carries no literal identifier the way "tell me about
# CVE-2021-44228" does, so the existing identifier/evidence machinery never
# sees it. A small local model answers these by confident recall instead of
# lookup and gets them wrong (e.g. Log4Shell -> CVE-2021-45046, the follow-up
# DoS CVE, instead of the original CVE-2021-44228). This extracts the named
# subject so the caller can ground the answer in retrieved evidence instead of
# letting generation invent or misremember the identifier.
_IDENTIFIER_ASK_RE = re.compile(
    r"\b(?:cve|cwe|capec)\b[^.?!]{0,30}?(?:identifier|number|id|code)?[^.?!]{0,10}?"
    r"\b(?:of|for|assigned\s+to|assigned\s+for)\b\s+"
    r"(?:the\s+)?(?P<name>[A-Z][\w.\-]*(?:\s+[A-Z0-9][\w.\-]*){0,3})",
    re.I,
)
_WHICH_IDENTIFIER_RE = re.compile(
    r"\bwhich\s+(?:cve|cwe|capec)\b[^.?!]{0,20}?\b(?:is|covers|applies\s+to|matches)\b\s+"
    r"(?:the\s+)?(?P<name>[A-Z][\w.\-]*(?:\s+[A-Z0-9][\w.\-]*){0,3})",
    re.I,
)
_IDENTIFIER_ASK_TRAILING_NOISE = re.compile(
    r"\s+(?:vulnerability|vulnerabilities|bug|flaw|exploit|attack|issue)s?\.?$", re.I)


def identifier_ask_subject(prompt: str) -> str | None:
    """If ``prompt`` asks which CVE/CWE/CAPEC identifies a named vulnerability
    (no literal identifier already given), return that name; else None."""
    text = prompt or ""
    match = _IDENTIFIER_ASK_RE.search(text) or _WHICH_IDENTIFIER_RE.search(text)
    if not match:
        return None
    name = _IDENTIFIER_ASK_TRAILING_NOISE.sub("", match.group("name")).strip()
    return name or None


@dataclass(frozen=True)
class ChatPolicy:
    domain: str
    user_goal: str
    target_type: str
    authorization_status: str
    requested_capability: str
    operational_detail: str
    potential_impact: str
    response_depth: str
    conversation_context: str
    instruction: str
    boundary: str | None = None

    @property
    def state(self) -> str:
        """Compatibility label exposed in diagnostics and existing callers."""
        if self.target_type == "prohibited":
            return "prohibited_harm"
        if self.target_type == "third_party" or self.target_type == "real_person":
            return "real_target"
        if self.user_goal in {"recover", "defend", "detect", "remediate"}:
            return "defensive"
        if self.target_type in {"user_owned", "lab", "ctf", "authorized_client"}:
            return "authorized_lab"
        if self.operational_detail in {"procedural", "immediately_actionable"} and self.authorization_status == "unknown":
            return "ambiguous"
        return "general"


_LAB = re.compile(r"\b(own|owned|my own|authorized|authorised|lab|ctf|capture the flag|sandbox|mock|locally|local|test account|staging|localhost|training platform|penetration test)\b", re.I)
_LAB_SPECIFIC = re.compile(r"\b(lab|ctf|capture the flag|sandbox|mock|locally|local|test account|staging|localhost|training platform)\b", re.I)
_REAL = re.compile(
    r"\b("
    r"another person(?:['’]s)?|someone(?:\s+else)?['’]s|somebody(?:\s+else)?['’]s|"
    r"anyone(?:\s+else)?['’]s|(?:my|a|the) friend(?:['’]s)?|(?:my|a|the) neighbou?r(?:['’]s)?|"
    r"my coworker(?:['’]s)?|my employer(?:['’]s)?|my school(?:['’]s)?|"
    r"a stranger(?:['’]s)?|stranger(?:['’]s)?|their account|real (?:person|account|company|system|target)|"
    r"a real target(?:['’]s)?|employee(?:['’]s)?|company(?:['’]s)?|client(?:['’]s)?|"
    r"(?:an?\s+)?(?:external|unrelated)\s+(?:person|user|account|company|organization|organisation|system|service|site|website|network|wireless network|wifi|application|app|server|host|target|tenant|device|endpoint|computer|router|access point|cloud|bucket|api)|"
    r"(?:against|on|to|from)\s+(?:someone|somebody|anyone)\s+else|"
    # 2026-09-30: named-relationship targets ("my ex-girlfriend's Instagram",
    # "my wife's phone") were falling through to "ambiguous" — a clarifying
    # question — instead of the real-target boundary, because only a short,
    # fixed relationship list (friend/neighbour/coworker/employer/school) was
    # covered. This is still a closed list, not general possessive-name
    # detection (that needs NER, not a regex), but it covers the common
    # phrasings the classifier was missing.
    r"(?:my|a|the) (?:ex[- ]?(?:girlfriend|boyfriend|wife|husband|partner)|"
    r"girlfriend|boyfriend|wife|husband|partner|fianc[ée]e?|"
    r"sister|brother|mom|mother|dad|father|parent|son|daughter|"
    r"roommate|classmate|teacher|professor|boss|manager|landlord|ex)(?:['’]s)?"
    r")\b", re.I)
_RECOVERY = re.compile(r"\b(recover|recovery|secure|secured|lock(ed)? out|reset|takeover|taken over|suspicious login|impersonat|compromised|harden|mfa|2fa)\b", re.I)
_OPERATIONAL = re.compile(
    r"\b(step[- ]by[- ]step|commands?|payloads?|"
    r"how\s+(?:do|can)\s+i\s+(?:hack|break\s+into|steal|bypass|phish|crack)|"
    r"hack\s+my|break\s+into|steal\s+.{0,30}credentials|"
    r"dump\s+.{0,30}credentials|evad(?:e|ing)|persistence)\b",
    re.I,
)

# A bare continuation / short follow-up carries NO new subject of its own —
# "yes", "it", "ig", "give me instructions", "give me code", "how to hack it".
# Such a turn must inherit the subject AND the boundary already established in
# the conversation, not be re-classified from scratch (which dropped an earlier
# real-third-party target back to "answer directly" and produced takeover steps).
_CONTINUATION = re.compile(
    r"^\s*(?:"
    r"(?:yes|yeah|yep|yup|ok|okay|sure|please|pls|continue|go on|keep going|more|"
    r"and|but|so|then|next|that|this|those|these|them|it|ig|same|again|k|do it)\b[\s\S]{0,30}"
    r"|(?:give|send|show|get) me (?:the |a |an |some )?(?:code|instructions?|steps?|examples?|"
    r"more|details?|commands?|payloads?|walkthrough|guide)"
    r"|show me(?: how)?"
    r"|(?:how (?:to|do i|can i) )?(?:do|hack|test|try|run|exploit|use|break into|access) it"
    r"|i (?:want|need|'?d like) to (?:test|try|do|hack|use) it"
    r")\s*[.!?]*\s*$",
    re.I,
)


def is_continuation(prompt: str) -> bool:
    """True when the turn is a short follow-up that refers back to the
    conversation rather than introducing its own subject."""
    p = (prompt or "").strip()
    if not p:
        return False
    if _CONTINUATION.match(p):
        return True
    # Short and anaphoric: <=4 words, contains a back-reference pronoun, and names
    # no standalone identifier (acronym/CVE/URL/product token).
    words = p.split()
    if len(words) <= 4 and re.search(r"\b(it|that|this|them|those|ig)\b", p, re.I) \
       and not re.search(r"CVE-|https?://|[A-Z]{3,}", p):
        return True
    return False


# ---------------------------------------------------------------------------
# Catastrophic-harm categories refused outright at the APPLICATION layer.
#
# 2026-09-30: Oyster's selectable models now include refusal-ablated weights
# (oyster-dolphin-v1, oyster-edge-*) whose transformation deliberately removed
# the model's own refusal behavior — see oyster/docs/AI_HANDOFF.md and the
# model lab's integration handoff ("raw ablation removes refusal behavior; do
# not rely on this model alone for physical-harm or real-target boundaries;
# retain Oyster's application policy controls"). The real-target boundary
# already short-circuits generation for attacks on real third parties; this
# adds the same structural boundary for the small set of catastrophic
# categories no security tool should ever assist with — CBRN/WMD uplift,
# mass-casualty/explosive-device construction, and CSAM.
#
# A match sets ChatPolicy.boundary, so routers/chat.py returns the boundary
# message and NEVER invokes the model (identical handling to real_target).
#
# These patterns are deliberately HIGH-PRECISION. They must never fire on
# ordinary cybersecurity education, malware/vuln analysis, defensive or
# incident-response work, owned-lab requests, or general science/history —
# that legitimate work is exactly what Oyster exists to help with, so a
# construction/production/weaponization INTENT (not a mere topic mention) is
# required. Tuned against tests/test_chat_policy_harm.py.
#
# Each category is split into INTENT patterns (an explicit request to create,
# obtain, weaponize or deploy — always boundaried, whatever else the message
# says) and TOPIC patterns (a bare mention — boundaried only when no
# defensive/understanding framing is present). Without the split, any
# defensive word anywhere ("...while avoiding detection") switched the whole
# check off.
_CBRN_INTENT = re.compile(
    r"(weaponi[sz]\w*\s+.{0,30}(pathogen|virus|bacteri\w*|anthrax|smallpox|plague|toxin)"
    r"|(synthesi[sz]\w*|produce|culture|cultivate|grow|make|manufactur\w*|obtain|acquire|aerosoli[sz]\w*|disperse|weaponi[sz]\w*)\s+.{0,40}(anthrax|smallpox|ricin|botulinum|nerve agent|sarin|\bvx\b|bubonic plague|bioweapon|chemical weapon|mustard gas)"
    r"|(build|make|construct|assemble|acquire|design|obtain)\s+.{0,30}(nuclear (bomb|weapon|device)|dirty bomb|radiological (dispersal|weapon|bomb))"
    r"|instructions for .{0,20}(dirty bomb|nerve agent|bioweapon|chemical weapon))",
    re.I)

_CBRN_TOPIC = re.compile(
    r"(bioweapon|biological weapon|nerve agent|sarin|\bvx\b\s+nerve|\bsoman\b|\btabun\b|mustard gas"
    r"|chemical weapon|dirty bomb|radiological (dispersal|weapon|bomb))",
    re.I)

# \bbomb\b excludes common security/household compounds (fork bomb, zip bomb,
# logic bomb, XML bomb, bath bomb) — those are ordinary Oyster questions.
_MASS_CASUALTY_INTENT = re.compile(
    r"((build|make|construct|assemble|create|design|detonate)\s+.{0,30}"
    r"(pipe bomb|\bied\b|explosive device|suicide (vest|belt)|car bomb|truck bomb|napalm|grenade"
    r"|(?<!fork )(?<!zip )(?<!logic )(?<!xml )(?<!bath )(?<!seed )\bbomb\b)"
    r"|maximi[sz]\w*\s+(casualties|deaths|the (death|body) (toll|count))"
    r"|kill\s+(as many|the most|many)\s+people"
    r"|poison\s+.{0,25}(water supply|reservoir|food supply|a crowd|the crowd)"
    r"|plan\w*\s+.{0,20}(mass shooting|school shooting))",
    re.I)

_MASS_CASUALTY_TOPIC = re.compile(r"(mass shooting|school shooting|mass casualt\w*)", re.I)

_CSAM = re.compile(
    r"(\bcsam\b|\bcsem\b|child (sexual abuse|sex abuse|sexual exploitation)|child (porn|pornography)"
    r"|(sexual\w*|explicit|nude|naked)\s+.{0,20}(child|children|minor|minors|underage|preteen|toddler)"
    r"|(child|children|minor|minors|underage|preteen)\s+.{0,20}(sexual\w*|explicit|nude|naked|porn))",
    re.I)

# Defensive/understanding framings that must NOT be boundaried even if a
# catastrophic keyword appears — detection, response, treatment, history, and
# conceptual "how does it work" questions route to normal handling instead.
_HARM_DEFENSIVE = re.compile(
    r"\b(detect|detection|respond to|response to|incident response|defend against|defence|defense|"
    r"protect against|mitigat\w*|treat\w*|treatment|symptoms|decontaminat\w*|"
    r"history of|what happened|how does .{0,20}work|how do .{0,20}work|how did .{0,20}work|"
    r"policy|regulation|treaty|nonproliferation|non-proliferation|safeguard\w*)\b",
    re.I)


def _catastrophic_category(current: str) -> str | None:
    """Return a catastrophic-harm category for an explicit request to CREATE
    such harm, or None. Defensive/understanding framings of a bare topic
    mention return None; they never excuse an explicit creation request."""
    if _CSAM.search(current):
        return "csam"  # no defensive exception — never assisted, in any framing
    if _CBRN_INTENT.search(current):
        return "cbrn"
    if _MASS_CASUALTY_INTENT.search(current):
        return "mass_casualty"
    if _HARM_DEFENSIVE.search(current):
        return None
    if _CBRN_TOPIC.search(current):
        return "cbrn"
    if _MASS_CASUALTY_TOPIC.search(current):
        return "mass_casualty"
    return None


def _catastrophic_boundary(category: str) -> str:
    if category == "csam":
        return (
            "I can’t help with anything involving the sexual exploitation of children. "
            "If you’ve encountered this material, report it to the NCMEC CyberTipline "
            "(report.cybertip.org) or your local authorities."
        )
    if category == "cbrn":
        return (
            "I can’t help create, obtain, or weaponize chemical, biological, radiological, "
            "or nuclear materials. I can explain the general science, the history, defensive "
            "detection and CBRN incident-response, or nonproliferation policy if that helps."
        )
    return (
        "I can’t help plan or build weapons or attacks meant to harm people. "
        "I can help with physical-security defense, threat detection, emergency "
        "response planning, or the general conceptual background instead."
    )


def _domain(text: str) -> str:
    domains = [
        ("network", r"wifi|wi-fi|network|dns|routing|firewall|vpn"),
        ("identity", r"account|password|session|token|mfa|authentication|credential"),
        ("web", r"web app|website|browser|api|http|sql injection|xss"),
        ("cloud", r"aws|azure|gcp|cloud|iam|bucket|kubernetes"),
        ("malware", r"malware|ransomware|trojan|botnet|payload"),
        ("privacy_crypto", r"privacy|cryptograph|encryption|hash|certificate|tls"),
        ("endpoint", r"linux|windows|macos|kernel|process|filesystem"),
        ("vulnerability_research", r"cve|vulnerability|exploit|reverse engineer|disassembl|binary"),
    ]
    found = [name for name, pattern in domains if re.search(pattern, text, re.I)]
    return found[0] if found else "general_security"


def _real_target_boundary(domain: str) -> str:
    overviews = {
        "network": "weak passwords, unsafe WPS, outdated firmware, rogue access points, or stolen credentials",
        "identity": "reused passwords, fake login pages, stolen sessions, or a compromised recovery channel",
        "web": "stolen credentials, injection flaws, session theft, or insecure account recovery",
        "cloud": "stolen keys, excessive permissions, exposed storage, or compromised identities",
        "endpoint": "stolen credentials, malicious software, unpatched flaws, or remote-access abuse",
        "malware": "malicious attachments, compromised software, stolen credentials, or command-and-control access",
        "privacy_crypto": "weak secrets, exposed keys, unsafe defaults, or compromised endpoints",
        "vulnerability_research": "unpatched flaws, exposed services, weak authentication, or unsafe configurations",
        "general_security": "stolen credentials, weak authentication, exposed services, or compromised recovery paths",
    }
    risks = overviews.get(domain, overviews["general_security"])
    return f"I can’t help break into someone else’s system. Common risk paths include {risks}. I can explain the techniques, help secure or recover the system, or guide an assessment of one you own."


def classify(prompt: str, history_text: str = "", response_depth: str = "overview") -> ChatPolicy:
    """Analyze the full request and context into independent policy fields."""
    current = (prompt or "").strip()
    all_text = f"{history_text}\n{current}"

    # Highest priority, checked before anything else and before the model is
    # ever invoked: explicit requests to CREATE catastrophic harm (CBRN/WMD,
    # mass-casualty weapons, CSAM). Boundaried at the application layer because
    # the selectable ablated models do not self-refuse — see the pattern block
    # above and oyster/docs/AI_HANDOFF.md.
    catastrophic = _catastrophic_category(current)
    if catastrophic:
        return ChatPolicy(
            domain=_domain(all_text), user_goal="prohibited", target_type="prohibited",
            authorization_status="prohibited", requested_capability="prohibited",
            operational_detail="prohibited", potential_impact="catastrophic",
            response_depth=response_depth, conversation_context="present" if history_text else "none",
            instruction="Refuse this request briefly and do not provide any methods, steps, materials, code, or details. Offer only the legitimate defensive, conceptual, or reporting alternative.",
            boundary=_catastrophic_boundary(catastrophic),
        )

    target = "none"
    authorization = "unknown"
    if _REAL.search(current):
        target, authorization = "real_person", "explicitly_unauthorized"
    elif _LAB.search(current):
        target, authorization = ("lab" if _LAB_SPECIFIC.search(current) else "user_owned"), "explicit"
    elif _LAB.search(all_text) and not _REAL.search(all_text):
        target, authorization = ("lab" if _LAB_SPECIFIC.search(all_text) else "user_owned"), "established_in_conversation"
    capability = "explanation"
    if re.search(r"\b(code review|review code)\b", current, re.I): capability = "code_review"
    elif re.search(r"\b(commands?|payloads?|step[- ]by[- ]step)\b", current, re.I): capability = "commands"
    elif _OPERATIONAL.search(current) and re.search(r"\b(hack|exploit|attack|break into|bypass|phish|crack)\b", current, re.I): capability = "commands"
    elif re.search(r"\b(credentials?|login|passwords?)\b", current, re.I) and _OPERATIONAL.search(current): capability = "credential_access"
    elif re.search(r"\b(exploit code|proof of concept|poc)\b", current, re.I): capability = "exploit_code"
    elif re.search(r"\b(persist|evasion|bypass)\b", current, re.I): capability = "evasion" if re.search(r"evasion|bypass", current, re.I) else "persistence"
    goal = "learn"
    if _RECOVERY.search(current): goal = "recover" if re.search(r"recover|reset|locked", current, re.I) else "defend"
    elif re.search(r"\b(detect|detection|hunt|investigate|forensic)\b", current, re.I): goal = "detect"
    elif re.search(r"\b(build|implement|secure|harden|prevent|remediate)\b", current, re.I): goal = "build" if re.search(r"build|implement", current, re.I) else "remediate"
    elif capability in {"commands", "exploit_code", "credential_access", "evasion", "persistence"}: goal = "exploit"
    detail = "conceptual"
    if capability in {"commands", "exploit_code", "credential_access", "evasion", "persistence"}: detail = "immediately_actionable" if target in {"real_person", "third_party"} else "procedural"
    elif response_depth in {"technical", "guided", "operational"}: detail = "technical"
    impact = "high" if capability in {"credential_access", "evasion", "persistence", "destructive_action"} else "dual_use"
    common = dict(domain=_domain(all_text), user_goal=goal, target_type=target,
                  authorization_status=authorization, requested_capability=capability,
                  operational_detail=detail, potential_impact=impact,
                  response_depth=response_depth, conversation_context="present" if history_text else "none")
    if _RECOVERY.search(current) and not _OPERATIONAL.search(current):
        return ChatPolicy(
            **common,
            instruction="Give direct, specific defensive or account-recovery help. "
                        "Include concrete checks, recovery steps, hardening, and evidence "
                        "preservation. Recovering or resetting the user's OWN account "
                        "through the provider's official recovery flow is account "
                        "recovery, not an authentication bypass — name it accurately and "
                        "never present a recovery procedure as bypassing authentication. "
                        "Steps that assume the password is already known do not explain "
                        "gaining access; say so instead of implying they do.",
        )
    # A current real-target statement overrides an earlier lab claim.
    if _REAL.search(current):
        return ChatPolicy(
            **common,
            instruction="Do not provide operational access, credential theft, phishing, session hijacking, or evasion instructions for a real third party. Keep the response brief and technically relevant.",
            boundary=_real_target_boundary(common["domain"]),
        )
    if _LAB.search(current):
        return ChatPolicy(
            **common,
            instruction="The user has established an owned lab, CTF, or approved test system. Provide substantial technical detail at the requested depth, with placeholders, validation points, cleanup, and defensive checks. Keep commands as text; never execute them. Do not ask for authorization again. Do not assume the user already has credentials or access, and do not invent specific vulnerabilities, CVEs, or working exploit code you cannot verify — state the prerequisites and assumptions instead.",
        )
    # A real third-party target established earlier in the conversation persists
    # across bare continuation follow-ups ("give me instructions", "it", "ig",
    # "give me code"). Without this, a short follow-up was re-classified as
    # "general" and the model produced account-takeover steps for the real target
    # named one turn earlier. A genuine current-turn pivot to an owned/authorized/
    # recovery context was already handled by the branches above, so this only
    # catches continuations that carry no new subject of their own.
    if is_continuation(current) and _REAL.search(history_text) \
       and not _LAB.search(all_text) and not _RECOVERY.search(current):
        return ChatPolicy(
            **{**common, "target_type": "real_person",
               "authorization_status": "explicitly_unauthorized"},
            instruction="A real third-party target was established earlier in this "
                        "conversation and this turn continues it. Do not provide "
                        "operational access, credential theft, phishing, session "
                        "hijacking, brute-forcing, or evasion steps against it. Keep it "
                        "brief and offer the legitimate alternative: recovering or "
                        "securing an account the user owns, or assessing a system they "
                        "are authorized to test.",
            boundary=_real_target_boundary(_domain(all_text)),
        )
    # Preserve an established lab context for short follow-ups, but never let a
    # generic follow-up turn an explicitly real target into a lab.
    if _LAB.search(all_text) and not _REAL.search(all_text):
        return ChatPolicy(**{**common, "target_type": "lab", "authorization_status": "established_in_conversation"}, instruction="Continue the established lab context with the requested technical depth. Keep commands as text and include validation and cleanup. Do not ask for authorization again.")
    if _OPERATIONAL.search(current):
        return ChatPolicy(
            **common,
            instruction="Answer the informational and defensive part directly. If the user asks for commands, payloads, credentials, persistence, evasion, or access against an unspecified target, keep the explanation conceptual and ask only one concise scope question: Is this a system you own or are authorized to test? Do not add a generic disclaimer or replace the answer with a canned paragraph.",
        )
    return ChatPolicy(
        **common,
        instruction="Answer the cybersecurity question directly and technically. "
                    "Explain mechanisms, assumptions, detection, mitigations, and "
                    "limitations without a generic disclaimer. If this turn is a short "
                    "follow-up ('it', 'ig', 'give me code', 'yes'), resolve the "
                    "reference from the conversation above and answer it — ask a "
                    "clarifying question only if the reference is genuinely ambiguous "
                    "given the history. Do not assume the user already has credentials, "
                    "and do not invent specific vulnerabilities, CVEs, or working "
                    "exploit code you cannot verify.",
    )
