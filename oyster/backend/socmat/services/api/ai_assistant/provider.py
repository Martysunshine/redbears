"""
AI provider abstraction for the investigation assistant.

Default: mock provider — deterministic, data-grounded, no external API needed.
Optional: set AI_PROVIDER=anthropic and ANTHROPIC_API_KEY to use Claude.

Environment variables:
  AI_PROVIDER       — "mock" (default) | "anthropic" | "openai" | "groq"
  ANTHROPIC_API_KEY — required when AI_PROVIDER=anthropic
  OPENAI_API_KEY    — required when AI_PROVIDER=openai
  GROQ_API_KEY      — required when AI_PROVIDER=groq
  AI_MODEL          — model ID override (default: claude-haiku-4-5-20251001)
                      Groq default: llama-3.3-70b-versatile
"""

import json
import os
import sys

from socmat.services.api.ai_assistant.prompts import SYSTEM_PROMPT, build_summarize_prompt, build_recommend_prompt

# Inside Oyster the default is the local Ollama model — nothing leaves the
# machine. The cloud providers (anthropic/openai/groq) remain available if a
# key is set, and "mock" stays as the deterministic offline fallback.
_AI_PROVIDER = os.getenv("AI_PROVIDER", "ollama").lower()
_AI_MODEL = os.getenv("AI_MODEL", "claude-haiku-4-5-20251001")

_DISCLAIMER = (
    "AI-generated analysis for analyst assistance only. "
    "All findings must be verified manually before taking action. "
    "This output is derived strictly from stored case data and does not replace analyst judgment."
)


# ── Public API ──────────────────────────────────────────────────────────────────

def call_ai(mode: str, context: dict) -> dict:
    """Dispatch to the configured provider. Returns a dict matching AIAnalysisResponse fields."""
    if _AI_PROVIDER == "anthropic":
        return _call_anthropic(mode, context)
    if _AI_PROVIDER == "openai":
        return _call_openai(mode, context)
    if _AI_PROVIDER == "groq":
        return _call_groq(mode, context)
    if _AI_PROVIDER == "ollama":
        return _call_ollama(mode, context)
    return _call_mock(mode, context)


def get_provider_name() -> str:
    return _AI_PROVIDER


# ── Mock provider ───────────────────────────────────────────────────────────────

def _call_mock(mode: str, context: dict) -> dict:
    case = context["case"]
    det_findings = context["detection_findings"]
    yara_results = context["yara_results"]
    net_results = context["network_results"]
    corr_findings = context["correlated_findings"]
    mitre_mappings = context["mitre_mappings"]
    evidence = context["evidence"]

    yara_hits = [r for r in yara_results if r["risk_score"] > 0]
    high_det = [f for f in det_findings if f["severity"] in ("high", "critical")]

    sources_with_data = sum([
        len(det_findings) > 0,
        len(yara_hits) > 0,
        len(net_results) > 0,
        len(corr_findings) > 0,
        len(mitre_mappings) > 0,
    ])

    confidence = _confidence_level(sources_with_data)
    incident_type = _infer_incident_type(context)
    missing = _identify_missing(context)

    if sources_with_data == 0:
        summary = (
            f'Case "{case["title"]}" has been opened with {case["severity"].upper()} severity, '
            f'but no analysis modules have been run yet. '
            f'Upload evidence files and run the available analysis modules to generate a meaningful assessment.'
        )
        key_evidence: list = []
        recs = [
            "Upload evidence files (Windows logs, Sysmon, Suricata, Zeek, suspicious files)",
            "Run Windows/Sysmon log analysis or Suricata alert analysis",
            "Run Sigma detection rules against normalized events",
            "Run YARA malware triage on any suspicious files",
            "Run correlation engine once multiple analysis modules have data",
            "Run MITRE ATT&CK mapping to identify technique coverage",
        ]
    else:
        summary = _build_mock_summary(case, det_findings, yara_hits, net_results, corr_findings, mitre_mappings, mode)
        key_evidence = _build_key_evidence(det_findings, yara_hits, net_results, corr_findings, mitre_mappings, high_det)
        recs = _build_recommendations(corr_findings, mitre_mappings, high_det, yara_hits)

    return {
        "summary": summary,
        "key_evidence": key_evidence,
        "likely_incident_type": incident_type,
        "confidence": confidence,
        "recommended_next_steps": recs,
        "missing_evidence": missing,
    }


def _confidence_level(sources_with_data: int) -> str:
    if sources_with_data == 0:
        return "insufficient"
    if sources_with_data == 1:
        return "low"
    if sources_with_data <= 3:
        return "medium"
    return "high"


def _infer_incident_type(context: dict) -> str:
    tactics = {m["tactic"] for m in context["mitre_mappings"]}
    corr_titles = [c["title"].lower() for c in context["correlated_findings"]]

    if "Command and Control" in tactics:
        return "Command and Control / C2 Beaconing"
    if "Credential Access" in tactics:
        return "Credential Theft / Authentication Attack"
    if "Exfiltration" in tactics:
        return "Data Exfiltration"
    if "Lateral Movement" in tactics:
        return "Lateral Movement"
    if any("ransomware" in t for t in corr_titles):
        return "Ransomware Activity"
    if any("malware" in t or "trojan" in t for t in corr_titles):
        return "Malware Infection"
    if "Defense Evasion" in tactics:
        return "Defense Evasion / Anti-Detection Activity"
    if "Persistence" in tactics:
        return "Persistence Establishment"
    if "Execution" in tactics:
        return "Malicious Code Execution"
    if context["detection_findings"]:
        return "Suspicious Activity — analyst review required"
    if context["yara_results"]:
        return "Suspicious File — malware triage inconclusive"
    return "Unknown — insufficient analysis data"


def _identify_missing(context: dict) -> list:
    missing = []
    if not context["evidence"]:
        missing.append("No evidence uploaded — upload log files or suspicious artifacts")
    if not context["detection_findings"]:
        missing.append("Sigma detection rules not run — run rules against normalized events")
    if not [r for r in context["yara_results"] if r["risk_score"] > 0]:
        if not context["yara_results"]:
            missing.append("YARA malware triage not performed — run YARA scan on uploaded files")
    if not context["network_results"]:
        missing.append("Network log analysis not performed — upload Zeek or Suricata logs")
    if not context["correlated_findings"]:
        missing.append("Correlation engine not run — run investigation correlation for multi-stage pattern detection")
    if not context["mitre_mappings"]:
        missing.append("MITRE ATT&CK mapping not run — map findings to identify technique coverage")
    if len(context["timeline_events"]) < 3:
        missing.append("Timeline has few events — more analysis data will populate the investigation timeline")
    return missing


def _build_mock_summary(case, det_findings, yara_hits, net_results, corr_findings, mitre_mappings, mode) -> str:
    parts = [
        f'Case "{case["title"]}" is a {case["severity"].upper()} severity incident '
        f'currently in {case["status"].upper()} status. '
    ]

    finding_parts = []
    if det_findings:
        finding_parts.append(f'{len(det_findings)} Sigma detection finding{"s" if len(det_findings) != 1 else ""}')
    if yara_hits:
        finding_parts.append(f'{len(yara_hits)} YARA triage hit{"s" if len(yara_hits) != 1 else ""}')
    if net_results:
        finding_parts.append(f'{len(net_results)} network analysis result{"s" if len(net_results) != 1 else ""}')
    if corr_findings:
        finding_parts.append(f'{len(corr_findings)} correlated finding{"s" if len(corr_findings) != 1 else ""}')

    if finding_parts:
        parts.append(f'Analysis has identified {", ".join(finding_parts)}. ')

    if mitre_mappings:
        tactics = sorted({m["tactic"] for m in mitre_mappings})
        parts.append(
            f'MITRE ATT&CK mapping covers {len(mitre_mappings)} technique{"s" if len(mitre_mappings) != 1 else ""} '
            f'across the following tactic{"s" if len(tactics) != 1 else ""}: {", ".join(tactics)}. '
        )

    high_corr = [c for c in corr_findings if c["confidence"] == "high"]
    if mode == "summarize" and high_corr:
        parts.append(
            f'High-confidence correlation suggests: {high_corr[0]["title"]}. '
        )

    return ''.join(parts).strip()


def _build_key_evidence(det_findings, yara_hits, net_results, corr_findings, mitre_mappings, high_det) -> list:
    points = []
    for f in high_det[:3]:
        points.append(f'[HIGH] Sigma: {f["rule_title"]} — {f["match_reason"] or "rule matched"}')
    for r in yara_hits[:3]:
        points.append(f'YARA triage: risk score {r["risk_score"]} — {r["summary"] or "matched malware signatures"}')
    for r in net_results[:2]:
        points.append(f'Network ({r["log_type"]}): {r["total_records"]} records, risk score {r["risk_score"]}')
    for cf in corr_findings[:2]:
        points.append(f'Correlation [{cf["confidence"].upper()}]: {cf["title"]}')
    techs = sorted({m["technique_id"] for m in mitre_mappings})
    if techs:
        points.append(f'ATT&CK techniques mapped: {", ".join(techs[:6])}')
    return points[:8]


def _build_recommendations(corr_findings, mitre_mappings, high_det, yara_hits) -> list:
    recs = []
    seen: set = set()

    for cf in corr_findings:
        action = cf.get("recommended_action") or ""
        if action and action not in seen:
            recs.append(action)
            seen.add(action)

    _TECH_RECS = {
        'T1110': 'Enforce account lockout policies and review privileged account activity.',
        'T1003': 'Check for credential dumping tools and rotate any exposed credentials immediately.',
        'T1059': 'Review scripting engine usage policies; enable Script Block Logging (EID 4103/4104).',
        'T1059.001': 'Enable PowerShell Constrained Language Mode and Script Block Logging.',
        'T1543.003': 'Audit newly installed services; verify binary paths against known-good baselines.',
        'T1053.005': 'Review scheduled tasks for unauthorized entries running as SYSTEM.',
        'T1027': 'Submit suspicious files to sandbox analysis; expand YARA/AV signature coverage.',
        'T1071.004': 'Investigate DNS query anomalies; consider sinkholing high-entropy domains.',
        'T1071.001': 'Review proxy/firewall logs for suspicious connections to uncategorized destinations.',
    }
    for tid, rec in _TECH_RECS.items():
        if any(m["technique_id"] == tid for m in mitre_mappings) and rec not in seen:
            recs.append(rec)
            seen.add(rec)

    if high_det and "Collect and preserve full event logs for affected hosts" not in seen:
        recs.append("Collect and preserve full event logs for affected hosts")
    if yara_hits and "Isolate or quarantine files flagged by YARA for further analysis" not in seen:
        recs.append("Isolate or quarantine files flagged by YARA for further analysis")
    if not recs:
        recs = [
            "Review all findings and apply containment measures based on case severity",
            "Escalate to senior analyst or IR team if indicators of compromise are confirmed",
            "Preserve evidence and document all investigative steps",
        ]
    return recs[:10]


# ── Anthropic provider ──────────────────────────────────────────────────────────

def _call_anthropic(mode: str, context: dict) -> dict:
    try:
        import anthropic  # noqa: PLC0415
    except ImportError as exc:
        raise RuntimeError("anthropic package not installed. Run: pip install anthropic") from exc

    api_key = os.getenv("ANTHROPIC_API_KEY", "")
    if not api_key:
        raise RuntimeError("ANTHROPIC_API_KEY environment variable is not set")

    client = anthropic.Anthropic(api_key=api_key)
    prompt = build_summarize_prompt(context) if mode == "summarize" else build_recommend_prompt(context)

    message = client.messages.create(
        model=_AI_MODEL,
        max_tokens=1024,
        system=SYSTEM_PROMPT,
        messages=[{"role": "user", "content": prompt}],
    )

    raw = message.content[0].text
    return _parse_ai_response(raw)


# ── OpenAI provider ─────────────────────────────────────────────────────────────

def _call_openai(mode: str, context: dict) -> dict:
    try:
        from openai import OpenAI  # noqa: PLC0415
    except ImportError as exc:
        raise RuntimeError("openai package not installed. Run: pip install openai") from exc

    api_key = os.getenv("OPENAI_API_KEY", "")
    if not api_key:
        raise RuntimeError("OPENAI_API_KEY environment variable is not set")

    client = OpenAI(api_key=api_key)
    prompt = build_summarize_prompt(context) if mode == "summarize" else build_recommend_prompt(context)

    response = client.chat.completions.create(
        model=os.getenv("AI_MODEL", "gpt-4o-mini"),
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        max_tokens=1024,
    )
    raw = response.choices[0].message.content or ""
    return _parse_ai_response(raw)


# ── Groq provider ───────────────────────────────────────────────────────────────

def _call_groq(mode: str, context: dict) -> dict:
    try:
        from openai import OpenAI  # noqa: PLC0415
    except ImportError as exc:
        raise RuntimeError("openai package not installed. Run: pip install openai") from exc

    api_key = os.getenv("GROQ_API_KEY", "")
    if not api_key:
        raise RuntimeError("GROQ_API_KEY environment variable is not set")

    client = OpenAI(api_key=api_key, base_url="https://api.groq.com/openai/v1")
    prompt = build_summarize_prompt(context) if mode == "summarize" else build_recommend_prompt(context)

    response = client.chat.completions.create(
        model=os.getenv("AI_MODEL", "llama-3.3-70b-versatile"),
        messages=[
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ],
        max_tokens=1024,
    )
    raw = response.choices[0].message.content or ""
    return _parse_ai_response(raw)


# ── Ollama provider (local — Oyster default) ────────────────────────────────────

def _call_ollama(mode: str, context: dict) -> dict:
    """Call Oyster's local Ollama. Keeps the 'nothing leaves the machine'
    invariant. Never fabricates: on any failure it degrades to the deterministic
    mock, annotated so the analyst knows the local model was unreachable."""
    import requests  # noqa: PLC0415

    base = os.getenv("OLLAMA_BASE_URL", "http://localhost:11434").rstrip("/")
    model = os.getenv("SOCMAT_AI_MODEL") or os.getenv("OYSTER_DEFAULT_MODEL", "dolphin3")
    prompt = build_summarize_prompt(context) if mode == "summarize" else build_recommend_prompt(context)
    try:
        resp = requests.post(
            f"{base}/api/chat",
            json={
                "model": model,
                "stream": False,
                "format": "json",  # coerce the JSON schema the system prompt asks for
                "messages": [
                    {"role": "system", "content": SYSTEM_PROMPT},
                    {"role": "user", "content": prompt},
                ],
                "options": {"temperature": 0.2},
            },
            timeout=240,
        )
        resp.raise_for_status()
        raw = resp.json().get("message", {}).get("content", "") or ""
    except Exception as exc:  # noqa: BLE001 — degrade honestly, never fabricate
        # The analyst is told the model was unreachable. WHERE it lives — the
        # exception text carries the host and port — is for the server log.
        print(f"  [socmat.ai] local model unavailable: {type(exc).__name__}: {exc}",
              file=sys.stderr)
        result = _call_mock(mode, context)
        result["summary"] = f"[local model unavailable] {result['summary']}"
        return result
    return _parse_ai_response(raw)


# ── Response parser ─────────────────────────────────────────────────────────────

def _parse_ai_response(raw: str) -> dict:
    text = raw.strip()
    if "```json" in text:
        text = text.split("```json", 1)[1].split("```", 1)[0].strip()
    elif "```" in text:
        text = text.split("```", 1)[1].split("```", 1)[0].strip()

    try:
        result = json.loads(text)
        return {
            "summary": str(result.get("summary", "")),
            "key_evidence": list(result.get("key_evidence", [])),
            "likely_incident_type": str(result.get("likely_incident_type", "Unknown")),
            "confidence": str(result.get("confidence", "medium")),
            "recommended_next_steps": list(result.get("recommended_next_steps", [])),
            "missing_evidence": list(result.get("missing_evidence", [])),
        }
    except Exception:
        return {
            "summary": raw,
            "key_evidence": [],
            "likely_incident_type": "See summary",
            "confidence": "medium",
            "recommended_next_steps": [],
            "missing_evidence": [],
        }
