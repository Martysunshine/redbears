"""
Live Elastic Connector endpoints.

GET  /elastic/live/status                       — connection status and cluster info
POST /elastic/live/search                       — run a free-form ES|QL query
POST /elastic/live/templates/{template_id}/run  — run a pre-approved hunt template
GET  /elastic/live/queries                      — list stored query history

Credentials are read from ELASTIC_URL and ELASTIC_API_KEY environment variables.
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

from socmat.integrations.elastic.connector import (  # noqa: E402
    is_configured,
    test_connection,
    run_esql_search,
    SAFETY_WARNING,
)
from socmat.integrations.elastic.hunt_templates import HUNT_TEMPLATES  # noqa: E402

from socmat.services.api.database import get_db
from socmat.services.api.models.elastic_live_query import ElasticLiveQuery
from socmat.services.api.schemas.elastic_live_schema import (
    ElasticStatusResponse,
    ElasticLiveSearchRequest,
    ElasticLiveTemplateRunRequest,
    ElasticLiveQueryResponse,
)

router = APIRouter(tags=["elastic-live"])


@router.get("/elastic/live/status", response_model=ElasticStatusResponse)
def get_elastic_live_status():
    """Test the live Elasticsearch connection and return cluster status."""
    result = test_connection()
    return ElasticStatusResponse(
        configured=result["configured"],
        connected=result["connected"],
        cluster_info=result.get("cluster_info"),
        error=result.get("error"),
        warning=result["warning"],
    )


@router.post("/elastic/live/search", response_model=ElasticLiveQueryResponse)
def run_elastic_live_search(
    body: ElasticLiveSearchRequest,
    db: Session = Depends(get_db),
):
    """
    Run a free-form ES|QL query against a live Elasticsearch instance.
    Stores query metadata and a sample of up to 20 results — not the full result set.
    """
    if not is_configured():
        raise HTTPException(
            status_code=503,
            # No environment-variable names in a response body: that is an
            # operator instruction, and it maps our configuration for a caller.
            detail="Live Elastic connector is not configured on this server.",
        )

    elastic_host = _extract_host(os.environ.get("ELASTIC_URL", ""))

    row = ElasticLiveQuery(
        case_id=body.case_id,
        esql_query=body.esql_query,
        template_id=None,
        index_pattern=body.index_pattern,
        max_results=body.max_results,
        status="pending",
        elastic_host=elastic_host,
    )
    db.add(row)
    db.commit()
    db.refresh(row)

    result = run_esql_search(body.esql_query, body.max_results)
    _apply_result(db, row, result)

    return _build_response(row)


@router.post(
    "/elastic/live/templates/{template_id}/run",
    response_model=ElasticLiveQueryResponse,
)
def run_elastic_live_template(
    template_id: str,
    body: ElasticLiveTemplateRunRequest,
    db: Session = Depends(get_db),
):
    """
    Run a pre-approved ES|QL hunt template against a live Elasticsearch instance.
    Only templates from the built-in library can be run this way.
    """
    if not is_configured():
        raise HTTPException(
            status_code=503,
            # No environment-variable names in a response body: that is an
            # operator instruction, and it maps our configuration for a caller.
            detail="Live Elastic connector is not configured on this server.",
        )

    template = next((t for t in HUNT_TEMPLATES if t["id"] == template_id), None)
    if not template:
        raise HTTPException(status_code=404, detail=f"Template '{template_id}' not found.")

    elastic_host = _extract_host(os.environ.get("ELASTIC_URL", ""))
    esql_query = template["esql_query"]

    row = ElasticLiveQuery(
        case_id=body.case_id,
        esql_query=esql_query,
        template_id=template_id,
        index_pattern=template.get("index_pattern"),
        max_results=body.max_results,
        status="pending",
        elastic_host=elastic_host,
    )
    db.add(row)
    db.commit()
    db.refresh(row)

    result = run_esql_search(esql_query, body.max_results)
    _apply_result(db, row, result)

    return _build_response(row)


@router.get("/elastic/live/queries", response_model=List[ElasticLiveQueryResponse])
def list_elastic_live_queries(
    case_id: Optional[int] = None,
    db: Session = Depends(get_db),
):
    """List stored live query history, newest first. Optionally filtered by case."""
    q = db.query(ElasticLiveQuery).order_by(ElasticLiveQuery.executed_at.desc())
    if case_id is not None:
        q = q.filter(ElasticLiveQuery.case_id == case_id)
    return [_build_response(r) for r in q.limit(100).all()]


# ── helpers ────────────────────────────────────────────────────────────────────

def _extract_host(url: str) -> str:
    """Extract hostname from URL for safe logging (no key, no credentials)."""
    try:
        parsed = urlparse(url)
        return parsed.hostname or url
    except Exception:
        return ""


def _apply_result(db: Session, row: ElasticLiveQuery, result: dict) -> None:
    """Write search result back to the row and commit."""
    sample = json.dumps(result["results"][:20], default=str) if result.get("results") else None
    row.result_count = result.get("result_count", 0)
    row.result_sample = sample
    row.status = "error" if result.get("error") else "completed"
    row.error_message = result.get("error")
    db.commit()
    db.refresh(row)


def _build_response(row: ElasticLiveQuery) -> ElasticLiveQueryResponse:
    return ElasticLiveQueryResponse(
        id=row.id,
        case_id=row.case_id,
        esql_query=row.esql_query,
        template_id=row.template_id,
        index_pattern=row.index_pattern,
        max_results=row.max_results or 50,
        result_count=row.result_count or 0,
        result_sample=row.result_sample,
        status=row.status,
        error_message=row.error_message,
        elastic_host=row.elastic_host,
        executed_at=row.executed_at.isoformat() if row.executed_at else "",
        warning=SAFETY_WARNING,
    )
