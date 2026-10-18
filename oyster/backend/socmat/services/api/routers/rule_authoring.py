"""
Detection rule authoring endpoints.

POST /rules/author              — generate Sigma/SPL/KQL/ES|QL drafts from a description
GET  /rules/author/event-types  — list supported event types for the UI dropdown

Output is draft-quality. All rules carry explicit quality disclaimers and
validation warnings. No rules are stored — this is a stateless generation tool.
"""

import sys
from pathlib import Path
from typing import List

from fastapi import APIRouter

from socmat.services.api.schemas.rule_authoring_schema import (
    RuleAuthorRequest,
    RuleDraftResponse,
    EventTypeOption,
)

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from socmat.integrations.rule_authoring.generator import (  # noqa: E402
    generate_rule_draft,
    EVENT_TYPE_LABELS,
)

router = APIRouter(tags=["rule-authoring"])


@router.post("/rules/author", response_model=RuleDraftResponse)
def author_rules(body: RuleAuthorRequest):
    """
    Generate Sigma YAML, Splunk SPL, Elastic KQL, and ES|QL rule drafts
    from a natural-language detection description.

    All output is experimental draft quality — review, test, and tune
    field values before deploying to production.
    """
    result = generate_rule_draft(
        description=body.description,
        event_type=body.event_type,
        example_fields=body.example_fields,
    )
    return RuleDraftResponse(**result)


@router.get("/rules/author/event-types", response_model=List[EventTypeOption])
def list_event_types():
    """Return supported event types for the rule authoring UI dropdown."""
    return [
        EventTypeOption(value=k, label=v)
        for k, v in EVENT_TYPE_LABELS.items()
    ]
