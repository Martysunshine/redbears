"""
Live Splunk Connector endpoints.

GET  /splunk/live/status                       — connection status and server info
POST /splunk/live/search                       — run a free-form SPL query
POST /splunk/live/templates/{template_id}/run  — run a pre-approved SPL template
GET  /splunk/live/queries                      — list stored query history

Credentials are read from SPLUNK_URL and SPLUNK_TOKEN environment variables.
No credentials are stored in the database — only hostname and query metadata.

WARNING: Do not use production credentials in development or demo environments.
"""

import json
import os
import sys
from pathlib import Path
from typing import List, Optional
from urllib.parse import urlparse

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

_REPO_ROOT = Path(__file__).resolve().parent.parent.parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from socmat.integrations.splunk.connector import (  # noqa: E402
    is_configured,
    test_connection,
    run_search,
    SAFETY_WARNING,
)
from socmat.integrations.splunk.query_templates import QUERY_TEMPLATES  # noqa: E402

from socmat.services.api.database import get_db
from socmat.services.api.models.splunk_live_query import SplunkLiveQuery
from socmat.services.api.schemas.splunk_live_schema import (
    SplunkStatusResponse,
    SplunkLiveSearchRequest,
    SplunkLiveTemplateRunRequest,
    SplunkLiveQueryResponse,
)

router = APIRouter(tags=["splunk-live"])


@router.get("/splunk/live/status", response_model=SplunkStatusResponse)
def get_splunk_live_status():
    """Test the live Splunk connection and return connection status."""
    result = test_connection()
    return SplunkStatusResponse(
        configured=result["configured"],
        connected=result["connected"],
        server_info=result.get("server_info"),
        error=result.get("error"),
        warning=result["warning"],
    )


@router.post("/splunk/live/search", response_model=SplunkLiveQueryResponse)
def run_splunk_live_search(
    body: SplunkLiveSearchRequest,
    db: Session = Depends(get_db),
):
    """
    Run a free-form SPL query against a live Splunk instance.
    Stores query metadata and a sample of up to 20 results — not the full result set.
    """
    if not is_configured():
        raise HTTPException(
            status_code=503,
            # No environment-variable names in a response body: that is an
            # operator instruction, and it maps our configuration for a caller.
            detail="Live Splunk connector is not configured on this server.",
        )

    splunk_host = _extract_host(os.environ.get("SPLUNK_URL", ""))

    row = SplunkLiveQuery(
        case_id=body.case_id,
        spl_query=body.spl_query,
        template_id=None,
        earliest_time=body.earliest_time,
        latest_time=body.latest_time,
        status="pending",
        splunk_host=splunk_host,
    )
    db.add(row)
    db.commit()
    db.refresh(row)

    result = run_search(body.spl_query, body.earliest_time, body.latest_time, body.max_results)
    _apply_result(db, row, result)

    return _build_response(row)


@router.post(
    "/splunk/live/templates/{template_id}/run",
    response_model=SplunkLiveQueryResponse,
)
def run_splunk_live_template(
    template_id: str,
    body: SplunkLiveTemplateRunRequest,
    db: Session = Depends(get_db),
):
    """
    Run a pre-approved SPL template against a live Splunk instance.
    Only templates from the built-in library can be run this way.
    """
    if not is_configured():
        raise HTTPException(
            status_code=503,
            # No environment-variable names in a response body: that is an
            # operator instruction, and it maps our configuration for a caller.
            detail="Live Splunk connector is not configured on this server.",
        )

    template = next((t for t in QUERY_TEMPLATES if t["id"] == template_id), None)
    if not template:
        raise HTTPException(status_code=404, detail=f"Template '{template_id}' not found.")

    splunk_host = _extract_host(os.environ.get("SPLUNK_URL", ""))

    row = SplunkLiveQuery(
        case_id=body.case_id,
        spl_query=template["spl_query"],
        template_id=template_id,
        earliest_time=body.earliest_time,
        latest_time=body.latest_time,
        status="pending",
        splunk_host=splunk_host,
    )
    db.add(row)
    db.commit()
    db.refresh(row)

    result = run_search(
        template["spl_query"],
        body.earliest_time,
        body.latest_time,
        body.max_results,
    )
    _apply_result(db, row, result)

    return _build_response(row)


@router.get("/splunk/live/queries", response_model=List[SplunkLiveQueryResponse])
def list_splunk_live_queries(
    case_id: Optional[int] = None,
    db: Session = Depends(get_db),
):
    """List stored live query history, newest first. Optionally filtered by case."""
    q = db.query(SplunkLiveQuery).order_by(SplunkLiveQuery.executed_at.desc())
    if case_id is not None:
        q = q.filter(SplunkLiveQuery.case_id == case_id)
    return [_build_response(r) for r in q.limit(100).all()]


# ── helpers ────────────────────────────────────────────────────────────────────

def _extract_host(url: str) -> str:
    """Extract hostname from URL for safe logging (no token, no credentials)."""
    try:
        parsed = urlparse(url)
        return parsed.hostname or url
    except Exception:
        return ""


def _apply_result(db: Session, row: SplunkLiveQuery, result: dict) -> None:
    """Write search result back to the row and commit."""
    sample = json.dumps(result["results"][:20], default=str) if result.get("results") else None
    row.result_count = result.get("result_count", 0)
    row.result_sample = sample
    row.status = "error" if result.get("error") else "completed"
    row.error_message = result.get("error")
    db.commit()
    db.refresh(row)


def _build_response(row: SplunkLiveQuery) -> SplunkLiveQueryResponse:
    return SplunkLiveQueryResponse(
        id=row.id,
        case_id=row.case_id,
        spl_query=row.spl_query,
        template_id=row.template_id,
        earliest_time=row.earliest_time,
        latest_time=row.latest_time,
        result_count=row.result_count or 0,
        result_sample=row.result_sample,
        status=row.status,
        error_message=row.error_message,
        splunk_host=row.splunk_host,
        executed_at=row.executed_at.isoformat() if row.executed_at else "",
        warning=SAFETY_WARNING,
    )
