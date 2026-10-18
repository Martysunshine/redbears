"""
Human-readable Sigma rule explanation generator.

Produces a structured explanation dict from a parsed rule dict without
requiring any external AI — all logic is deterministic.
"""

from typing import Any, Dict, List


_MITRE_TACTIC_NAMES: Dict[str, str] = {
    "initial_access": "Initial Access",
    "execution": "Execution",
    "persistence": "Persistence",
    "privilege_escalation": "Privilege Escalation",
    "defense_evasion": "Defense Evasion",
    "credential_access": "Credential Access",
    "discovery": "Discovery",
    "lateral_movement": "Lateral Movement",
    "collection": "Collection",
    "command_and_control": "Command and Control",
    "exfiltration": "Exfiltration",
    "impact": "Impact",
}


def _extract_mitre(tags: List[str]) -> Dict[str, List[str]]:
    """Split attack.* tags into technique IDs and tactic names."""
    techniques: List[str] = []
    tactics: List[str] = []
    for tag in tags:
        low = tag.lower()
        if not low.startswith("attack."):
            continue
        part = low[7:]
        if part.startswith("t") and part[1:].replace(".", "").isdigit():
            techniques.append(part.upper())
        else:
            human = _MITRE_TACTIC_NAMES.get(part, part.replace("_", " ").title())
            tactics.append(human)
    return {"techniques": techniques, "tactics": tactics}


def _summarise_detection(detection: Dict[str, Any]) -> List[str]:
    """Convert a Sigma detection block into readable field-condition strings."""
    lines: List[str] = []
    for key, val in detection.items():
        if key == "condition":
            continue
        if not isinstance(val, dict):
            continue
        for field, matcher in val.items():
            parts = field.split("|")
            field_name = parts[0]
            modifier = parts[1] if len(parts) > 1 else "equals"
            if isinstance(matcher, list):
                values = [str(v) for v in matcher]
                desc = f"`{field_name}` {modifier}: {', '.join(values[:5])}"
                if len(values) > 5:
                    desc += f" (+ {len(values) - 5} more)"
            else:
                desc = f"`{field_name}` {modifier}: `{matcher}`"
            lines.append(desc)
    return lines


def _investigation_steps(rule: Dict[str, Any]) -> List[str]:
    """Generate contextual investigation steps based on rule properties."""
    level = rule.get("level", "medium")
    logsource = rule.get("logsource", {})
    category = logsource.get("category", "").lower()
    tags = [t.lower() for t in rule.get("tags", [])]
    steps: List[str] = []

    if "process_creation" in category:
        steps.append("Review the full command line and parent process for context.")
        steps.append("Check if the process image is a known-good application or admin tool.")
        steps.append("Investigate the user account that launched the process.")

    if "network_connection" in category or "network" in category:
        steps.append("Identify the destination IP/hostname and check against threat intelligence.")
        steps.append("Look for related process creation events on the same host.")
        steps.append("Review connection frequency and data volume for exfiltration indicators.")

    if "dns" in category:
        steps.append("Inspect the queried domain for typosquatting, DGA, or excessive length.")
        steps.append("Check if the same domain was queried from other internal hosts recently.")

    if any("t1110" in t for t in tags):
        steps.append("Count authentication failures and successes per source IP within the time window.")
        steps.append("Check if a successful logon follows the failure burst — indicates credential stuffing.")

    if any("t1059" in t for t in tags):
        steps.append("Decode any Base64-encoded or obfuscated command line arguments.")
        steps.append("Review spawned child processes for follow-on execution.")

    if any("t1543" in t for t in tags):
        steps.append("Inspect the service binary path for suspicious or unsigned executables.")
        steps.append("Check service startup type, running account, and creation timestamp.")

    if any("t1027" in t for t in tags):
        steps.append("Attempt to decode the obfuscated content for further analysis.")
        steps.append("Compare against known-good scripts or admin automation in your environment.")

    if not steps:
        steps.append("Review the triggering event in the context of surrounding timeline events.")
        steps.append("Correlate with other findings from the same host or user account.")

    if level in ("high", "critical"):
        steps.append("Escalate immediately if confirmed — document the finding in the case timeline.")

    return steps


def explain(rule: Dict[str, Any]) -> Dict[str, Any]:
    """Return a structured, human-readable explanation for a Sigma rule dict."""
    mitre = _extract_mitre(rule.get("tags", []))
    detection_fields = _summarise_detection(rule.get("detection", {}))
    steps = _investigation_steps(rule)
    logsource = rule.get("logsource", {})

    ls_parts = []
    if logsource.get("product"):
        ls_parts.append(logsource["product"].title())
    if logsource.get("category"):
        ls_parts.append(logsource["category"].replace("_", " "))
    if logsource.get("service"):
        ls_parts.append(f"service: {logsource['service']}")
    log_source_desc = " / ".join(ls_parts) if ls_parts else "any log source"

    return {
        "summary": rule.get("description") or f"Detects: {rule['title']}",
        "log_source": log_source_desc,
        "detection_fields": detection_fields,
        "mitre_tactics": mitre["tactics"],
        "mitre_techniques": mitre["techniques"],
        "false_positives": rule.get("falsepositives", []),
        "investigation_steps": steps,
    }
