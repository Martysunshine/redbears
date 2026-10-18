"""
MVP Sigma rule matcher.

Evaluates a limited subset of Sigma detection logic against normalised
Windows/Sysmon events.  Supports:
  - Single-selection conditions (condition: selection)
  - Modifiers: contains, endswith, startswith, contains|all
  - AND logic across fields within a selection
  - OR logic when a field maps to a list of values

Unsupported (skipped gracefully):
  - |re (regex) modifier
  - Multi-group conditions (1 of selection*, selection1 and selection2, etc.)
  - Fields not present in the normalized_events schema
"""

from typing import Any, Dict, List, Optional, Tuple


# Maps lowercase Sigma field names to normalized_events column names.
SIGMA_FIELD_MAP: Dict[str, str] = {
    "eventid": "event_id",
    "image": "process_name",
    "newprocessname": "process_name",
    "parentimage": "parent_process_name",
    "parentprocessname": "parent_process_name",
    "commandline": "command_line",
    "computer": "host",
    "computername": "host",
    "hostname": "host",
    "targetusername": "user",
    "subjectusername": "user",
    "username": "user",
    "user": "user",
    "ipaddress": "source_ip",
    "sourceip": "source_ip",
    "src_ip": "source_ip",
    "destinationip": "destination_ip",
    "destinationhostname": "destination_ip",
    "destinationport": "destination_port",
    "channel": "source",
}


def _check_field(
    event: Dict[str, Any],
    sigma_field: str,
    values: Any,
    modifiers: List[str],
) -> Optional[bool]:
    """
    Evaluate a single Sigma field condition against one event.

    Returns:
        True  — condition passes
        False — condition fails
        None  — field or modifier is unsupported; caller should skip this check
    """
    if "re" in modifiers:
        return None  # Regex not supported in MVP

    db_field = SIGMA_FIELD_MAP.get(sigma_field.lower())
    if db_field is None:
        return None  # Unknown field — skip rather than fail

    raw_val = event.get(db_field)
    if raw_val is None:
        return False  # Known field exists in schema but NULL for this event

    event_val = str(raw_val)

    val_list = values if isinstance(values, list) else [values]
    val_list = [str(v) for v in val_list if v is not None]
    if not val_list:
        return False

    want_all = "all" in modifiers

    if "contains" in modifiers:
        def check(v: str) -> bool:
            return v.lower() in event_val.lower()
    elif "endswith" in modifiers:
        def check(v: str) -> bool:
            return event_val.lower().endswith(v.lower())
    elif "startswith" in modifiers:
        def check(v: str) -> bool:
            return event_val.lower().startswith(v.lower())
    else:
        def check(v: str) -> bool:
            return event_val.lower() == v.lower()

    if want_all:
        return all(check(v) for v in val_list)
    return any(check(v) for v in val_list)


def _match_selection(
    event: Dict[str, Any],
    selection: Dict[str, Any],
) -> Tuple[bool, int]:
    """
    Check ALL field conditions in a Sigma selection group (AND logic).

    Returns (matched, known_fields_evaluated):
        matched              — True if every evaluated condition passed
        known_fields_evaluated — number of fields that were actually checked
                                 (0 means no supported fields; caller should
                                  treat the whole selection as unevaluable)
    """
    known = 0
    for field_mod, values in selection.items():
        parts = field_mod.split("|")
        sigma_field = parts[0]
        modifiers = [m.lower() for m in parts[1:]]

        result = _check_field(event, sigma_field, values, modifiers)
        if result is None:
            continue  # Unsupported — skip without failing
        known += 1
        if not result:
            return False, known

    return True, known


def match_rule(
    rule: Dict[str, Any],
    event: Dict[str, Any],
) -> Optional[str]:
    """
    Try to match one Sigma rule against one normalized event.

    Returns a human-readable match-reason string if the rule fires,
    or None if it does not match (or cannot be evaluated in MVP).
    """
    detection = rule.get("detection", {})
    if not isinstance(detection, dict):
        return None

    condition = str(detection.get("condition", "")).strip().lower()
    if not condition:
        return None

    # Collect named selection groups (all keys except "condition")
    groups = {
        k: v
        for k, v in detection.items()
        if k != "condition" and isinstance(v, dict)
    }
    if not groups:
        return None

    # MVP: only handle simple "condition: <single_group_name>"
    if condition not in groups:
        return None  # Complex condition — not supported in Phase 7

    sel = groups[condition]
    matched, known = _match_selection(event, sel)

    if known == 0:
        return None  # No known fields could be evaluated — skip
    if matched:
        return f"Matched '{condition}' selection"

    return None


def run_rules_against_events(
    rules: List[Dict[str, Any]],
    events: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    Run a list of Sigma rules against a list of normalised event dicts.

    Each event dict must include an 'id' key (the DB row ID).

    Returns a list of finding dicts:
        rule_id, rule_title, severity, matched_event_id,
        match_reason, event_id_str, event_timestamp
    """
    findings: List[Dict[str, Any]] = []
    for event in events:
        for rule in rules:
            reason = match_rule(rule, event)
            if reason:
                findings.append({
                    "rule_id": rule["id"],
                    "rule_title": rule["title"],
                    "severity": rule.get("level", "medium"),
                    "matched_event_id": event["id"],
                    "match_reason": reason,
                    "event_id_str": event.get("event_id"),
                    "event_timestamp": event.get("timestamp"),
                })
    return findings
