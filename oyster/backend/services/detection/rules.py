"""Detection rules, paired baseline/improved per scenario.

Each baseline is DELIBERATELY WEAK and explicitly marked ``is_demo_baseline =
True`` — it exists to give the validation flow something real to improve on,
not as a credible production rule. Never render one without that label.

Rules evaluate real telemetry events (services/lab/telemetry_proxy.py's JSONL
records) plus whatever non-sensitive context a scenario recorded about its own
run (e.g. which synthetic account owns which basket id) — never the model's
narration of what happened.
"""
from __future__ import annotations

import dataclasses
import re
from typing import Callable


@dataclasses.dataclass
class RuleMatch:
    matched: bool
    matched_events: list[dict]
    reasoning: str


@dataclasses.dataclass
class DetectionRule:
    id: str
    scenario_id: str
    label: str
    description: str
    is_demo_baseline: bool
    evaluate: Callable[[list[dict], dict], RuleMatch]


# --- SQL injection login bypass ---------------------------------------------

def _sqli_baseline(events: list[dict], ctx: dict) -> RuleMatch:
    matched = [e for e in events
               if e.get("path") == "/rest/user/login" and e.get("body_preview")
               and "DROP TABLE" in e["body_preview"].upper()]
    return RuleMatch(bool(matched), matched,
                     "Looks only for the literal keyword 'DROP TABLE' in the login request body. "
                     "A comment-based auth-bypass payload contains no such keyword, so this rule "
                     "misses it by design — a deliberately weak demo baseline.")


_SQLI_MARKER = re.compile(r"(--|#|/\*)|'\s*(or|and)\b", re.I)


def _sqli_improved(events: list[dict], ctx: dict) -> RuleMatch:
    matched = [e for e in events
               if e.get("path") == "/rest/user/login" and e.get("status") == 200 and e.get("body_preview")
               and _SQLI_MARKER.search(e["body_preview"])]
    return RuleMatch(bool(matched), matched,
                     "Flags a successful (200) login whose submitted email contains a SQL "
                     "comment marker (--, #, /*) or a quoted boolean operator (' OR / ' AND).")


SQLI_BASELINE = DetectionRule("sqli_baseline", "sqli_login_bypass", "Baseline: keyword match on 'DROP TABLE'",
                              "Demo configuration — intentionally too narrow to catch an auth-bypass payload.",
                              True, _sqli_baseline)
SQLI_IMPROVED = DetectionRule("sqli_improved", "sqli_login_bypass",
                              "Improved: successful login + SQL metacharacter in email field",
                              "Correlates the login outcome with injection-shaped input in the credential field.",
                              False, _sqli_improved)


# --- IDOR / broken access control on /rest/basket/:id -----------------------

def _idor_baseline(events: list[dict], ctx: dict) -> RuleMatch:
    matched = [e for e in events if e.get("path", "").startswith("/rest/basket/") and e.get("status") == 403]
    return RuleMatch(bool(matched), matched,
                     "Only alerts on an HTTP 403 from the basket endpoint. Juice Shop's basket route "
                     "never returns 403 for this issue (it returns 200 with the other user's data), "
                     "so this rule structurally cannot catch it — a deliberately weak demo baseline.")


def _idor_improved(events: list[dict], ctx: dict) -> RuleMatch:
    bid_owner: dict = ctx.get("bid_owner", {})
    matched = []
    for e in events:
        if not e.get("path", "").startswith("/rest/basket/") or e.get("status") != 200:
            continue
        try:
            requested_bid = int(e["path"].rsplit("/", 1)[-1])
        except ValueError:
            continue
        owner = bid_owner.get(requested_bid)
        actor = e.get("actor")
        if owner and actor and actor != owner:
            matched.append(e)
    return RuleMatch(bool(matched), matched,
                     "Flags a successful basket read where the requesting identity does not match "
                     "the basket's recorded owner. (In this lab, ownership is supplied by the test "
                     "harness's own ground truth — a production deployment would need the app to "
                     "log the authenticated principal itself, e.g. the JWT's own basket-id claim; "
                     "Juice Shop does not emit that today, which is itself a real instrumentation gap.)")


IDOR_BASELINE = DetectionRule("idor_baseline", "idor_basket_access", "Baseline: alert only on HTTP 403",
                              "Demo configuration — the vulnerable route never returns 403, so this never fires.",
                              True, _idor_baseline)
IDOR_IMPROVED = DetectionRule("idor_improved", "idor_basket_access",
                              "Improved: requester identity vs. recorded basket owner",
                              "Correlates each successful basket read against which synthetic identity actually owns that basket id.",
                              False, _idor_improved)

RULES: dict[str, DetectionRule] = {r.id: r for r in
                                   (SQLI_BASELINE, SQLI_IMPROVED, IDOR_BASELINE, IDOR_IMPROVED)}


def rules_for_scenario(scenario_id: str) -> list[DetectionRule]:
    return [r for r in RULES.values() if r.scenario_id == scenario_id]
