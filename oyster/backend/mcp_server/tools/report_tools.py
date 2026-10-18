from __future__ import annotations

import json

import config
from services import evidence_service, ollama_service, scope_service

_PROMPTS_DIR = config.PROMPTS_DIR


def create_finding(
    title: str,
    severity: str,
    endpoint: str,
    description: str,
    steps_to_reproduce: str = "",
    recommended_fix: str = "",
) -> dict:
    try:
        entry = evidence_service.log_finding({
            "title": title,
            "severity": severity,
            "endpoint": endpoint,
            "steps_to_reproduce": steps_to_reproduce,
            "screenshot_notes": description,
            "recommended_fix": recommended_fix,
        })
        return {"created": True, "finding": entry}
    except Exception as exc:
        return {"error": f"create_finding failed: {exc}"}


def list_findings() -> dict:
    try:
        findings = evidence_service.list_findings()
        return {"findings": findings, "total": len(findings)}
    except Exception as exc:
        return {"error": f"list_findings failed: {exc}"}


def score_risk(
    severity: str,
    exploitability: str = "medium",
    attack_vector: str = "network",
    impact: str = "medium",
) -> dict:
    sev_score = {"critical": 9.5, "high": 7.5, "medium": 5.0, "low": 2.5, "info": 0.0}
    exp_score = {"easy": 3.9, "medium": 2.0, "hard": 0.8}
    av_score = {"network": 3.9, "adjacent": 2.8, "local": 1.8, "physical": 0.7}
    imp_score = {"high": 3.6, "medium": 2.0, "low": 0.8, "none": 0.0}

    base = sev_score.get(severity.lower(), 5.0)
    exp = exp_score.get(exploitability.lower(), 2.0)
    av = av_score.get(attack_vector.lower(), 3.9)
    imp = imp_score.get(impact.lower(), 2.0)

    score = round(min(10.0, base * 0.5 + exp * 0.15 + av * 0.2 + imp * 0.15), 1)
    rating = (
        "CRITICAL" if score >= 9.0
        else "HIGH" if score >= 7.0
        else "MEDIUM" if score >= 4.0
        else "LOW" if score >= 0.1
        else "NONE"
    )
    return {
        "score": score,
        "rating": rating,
        "cvss_vector": (
            f"AV:{attack_vector[0].upper()}/E:{exploitability[0].upper()}"
            f"/I:{impact[0].upper()}"
        ),
        "inputs": {
            "severity": severity,
            "exploitability": exploitability,
            "attack_vector": attack_vector,
            "impact": impact,
        },
        "note": "Simplified CVSS-lite — use official CVSS 3.1 calculator for formal reports",
    }


async def generate_executive_summary(engagement_name: str, model: str = "dolphin3") -> dict:
    try:
        findings = evidence_service.list_findings()
        scope = scope_service.load_scope()
        counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.get("severity", "info").lower()
            counts[sev] = counts.get(sev, 0) + 1

        summary_lines = [
            {"title": f.get("title"), "severity": f.get("severity"), "endpoint": f.get("endpoint")}
            for f in findings
        ]
        prompt = (
            f"Write an executive summary for a penetration test engagement.\n\n"
            f"ENGAGEMENT: {engagement_name}\n"
            f"AUTHORIZED BY: {scope.get('authorized_by', 'N/A')}\n"
            f"DATE RANGE: {scope.get('start_date', 'N/A')} to {scope.get('end_date', 'N/A')}\n"
            f"FINDINGS: Critical={counts['critical']}, High={counts['high']}, "
            f"Medium={counts['medium']}, Low={counts['low']}\n\n"
            f"FINDING TITLES:\n{json.dumps(summary_lines, indent=2)}\n\n"
            f"Write 2 paragraphs for a non-technical executive audience:\n"
            f"1. Overall risk posture and the most critical findings.\n"
            f"2. Recommended immediate actions and strategic security priorities.\n"
            f"Be concise, business-focused, and avoid jargon."
        )
        ollama_model = config.resolve_model(model, "dolphin3")
        summary = await ollama_service.generate(prompt, ollama_model)
        return {
            "engagement_name": engagement_name,
            "executive_summary": summary,
            "finding_counts": counts,
            "total_findings": len(findings),
            "model": model,
        }
    except Exception as exc:
        return {"error": f"generate_executive_summary failed: {exc}"}


async def remediation_guidance(
    finding_type: str,
    context: str = "",
    model: str = "dolphin3",
) -> dict:
    try:
        prompt = (
            f"You are a senior application security engineer.\n\n"
            f"VULNERABILITY TYPE: {finding_type}\n"
            f"CONTEXT: {context or 'None provided'}\n\n"
            f"Provide actionable remediation guidance:\n"
            f"1. Root cause (2 sentences)\n"
            f"2. Immediate mitigation steps (numbered list)\n"
            f"3. Long-term fix (numbered list)\n"
            f"4. Relevant standards: OWASP, CWE, NIST references\n"
            f"5. Estimated effort: hours or days\n\n"
            f"Be specific and technical."
        )
        ollama_model = config.resolve_model(model, "dolphin3")
        guidance = await ollama_service.generate(prompt, ollama_model)
        return {"finding_type": finding_type, "guidance": guidance, "model": model}
    except Exception as exc:
        return {"error": f"remediation_guidance failed: {exc}"}


async def generate_report(engagement_name: str, model: str = "dolphin3") -> dict:
    try:
        findings = evidence_service.list_findings()
        if not findings:
            return {"error": "No findings logged yet. Use create_finding first."}
        scope = scope_service.load_scope()
        prompt_path = _PROMPTS_DIR / "report_prompt.txt"
        template = prompt_path.read_text(encoding="utf-8").strip() if prompt_path.exists() else ""
        findings_json = json.dumps(findings, indent=2)
        prompt = (
            f"{template}\n\n"
            f"ENGAGEMENT: {engagement_name}\n"
            f"AUTHORIZED BY: {scope.get('authorized_by', 'N/A')}\n"
            f"DATE RANGE: {scope.get('start_date', 'N/A')} to {scope.get('end_date', 'N/A')}\n\n"
            f"FINDINGS INPUT:\n{findings_json}\n\n"
            f"Generate the full professional penetration testing report."
        )
        ollama_model = config.resolve_model(model, "dolphin3")
        report = await ollama_service.generate(prompt, ollama_model)
        return {"engagement_name": engagement_name, "report": report, "finding_count": len(findings), "model": model}
    except Exception as exc:
        return {"error": f"generate_report failed: {exc}"}
