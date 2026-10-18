"""
MCP server status endpoints.

GET /mcp/tools       — list available MCP tools and their parameter requirements
GET /mcp/tool-calls  — recent tool call log entries (most recent first)
"""

import json
import os
from pathlib import Path
from typing import Any, List, Optional

from fastapi import APIRouter
from pydantic import BaseModel

router = APIRouter(tags=["mcp"])

# Resolve log file path: default to services/mcp-server/mcp_tool_calls.jsonl
_LOG_FILE_DEFAULT = (
    Path(__file__).resolve().parent.parent.parent / "mcp-server" / "mcp_tool_calls.jsonl"
)
_LOG_FILE = Path(os.getenv("MCP_LOG_FILE", str(_LOG_FILE_DEFAULT)))

_TOOL_CATALOG: List[dict] = [
    {
        "name": "list_cases",
        "description": "List all investigation cases.",
        "requires_case_id": False,
        "requires_evidence_id": False,
        "category": "read",
    },
    {
        "name": "get_case_summary",
        "description": "Structured summary of a case including correlations and MITRE mappings.",
        "requires_case_id": True,
        "requires_evidence_id": False,
        "category": "read",
    },
    {
        "name": "list_case_evidence",
        "description": "List evidence files for a case.",
        "requires_case_id": True,
        "requires_evidence_id": False,
        "category": "read",
    },
    {
        "name": "get_case_timeline",
        "description": "Chronological investigation timeline for a case.",
        "requires_case_id": True,
        "requires_evidence_id": False,
        "category": "read",
    },
    {
        "name": "run_windows_log_analysis",
        "description": "Analyze Windows/Sysmon event logs — static analysis only.",
        "requires_case_id": True,
        "requires_evidence_id": True,
        "category": "analysis",
    },
    {
        "name": "run_suricata_analysis",
        "description": "Analyze Suricata IDS/IPS alert logs — static analysis only.",
        "requires_case_id": True,
        "requires_evidence_id": True,
        "category": "analysis",
    },
    {
        "name": "run_zeek_analysis",
        "description": "Analyze Zeek network logs — static analysis only.",
        "requires_case_id": True,
        "requires_evidence_id": True,
        "category": "analysis",
    },
    {
        "name": "run_sigma_rules",
        "description": "Run attached Sigma detection rules against normalized events.",
        "requires_case_id": True,
        "requires_evidence_id": False,
        "category": "detection",
    },
    {
        "name": "run_yara_scan",
        "description": "Run YARA malware triage — static analysis only.",
        "requires_case_id": True,
        "requires_evidence_id": True,
        "category": "detection",
    },
    {
        "name": "run_correlation",
        "description": "Correlate findings across all analysis modules.",
        "requires_case_id": True,
        "requires_evidence_id": False,
        "category": "analysis",
    },
    {
        "name": "run_mitre_mapping",
        "description": "Map findings to MITRE ATT&CK techniques and tactics.",
        "requires_case_id": True,
        "requires_evidence_id": False,
        "category": "analysis",
    },
    {
        "name": "generate_incident_report",
        "description": "Generate a Markdown security incident report.",
        "requires_case_id": True,
        "requires_evidence_id": False,
        "category": "reporting",
    },
    {
        "name": "check_splunk_connection",
        "description": "Check whether the live Splunk connector is configured and reachable.",
        "requires_case_id": False,
        "requires_evidence_id": False,
        "category": "splunk",
    },
    {
        "name": "run_splunk_query",
        "description": "Run a free-form SPL query against a live Splunk instance.",
        "requires_case_id": False,
        "requires_evidence_id": False,
        "category": "splunk",
    },
    {
        "name": "run_splunk_template",
        "description": "Run a pre-approved SPL template (failed_logins, powershell_encoded, etc.) against a live Splunk instance.",
        "requires_case_id": False,
        "requires_evidence_id": False,
        "category": "splunk",
    },
    {
        "name": "list_splunk_queries",
        "description": "List stored Splunk live query history, optionally filtered by case.",
        "requires_case_id": False,
        "requires_evidence_id": False,
        "category": "splunk",
    },
    {
        "name": "analyze_splunk_export",
        "description": "Parse and analyze an uploaded Splunk CSV/JSON export file.",
        "requires_case_id": True,
        "requires_evidence_id": True,
        "category": "splunk",
    },
    {
        "name": "check_elastic_connection",
        "description": "Check whether the live Elasticsearch connector is configured and reachable.",
        "requires_case_id": False,
        "requires_evidence_id": False,
        "category": "elastic",
    },
    {
        "name": "run_elastic_query",
        "description": "Run a free-form ES|QL query against a live Elasticsearch instance.",
        "requires_case_id": False,
        "requires_evidence_id": False,
        "category": "elastic",
    },
    {
        "name": "run_elastic_template",
        "description": "Run a pre-approved ES|QL hunt template (encoded_powershell, dns_tunneling, etc.) against a live Elasticsearch instance.",
        "requires_case_id": False,
        "requires_evidence_id": False,
        "category": "elastic",
    },
    {
        "name": "list_elastic_queries",
        "description": "List stored Elasticsearch live query history, optionally filtered by case.",
        "requires_case_id": False,
        "requires_evidence_id": False,
        "category": "elastic",
    },
    {
        "name": "analyze_elastic_export",
        "description": "Parse and analyze an uploaded Kibana NDJSON or Elastic export file.",
        "requires_case_id": True,
        "requires_evidence_id": True,
        "category": "elastic",
    },
]


class ToolCallLog(BaseModel):
    tool_name: str
    case_id: Optional[int]
    timestamp: str
    success: bool
    error: Optional[str]


@router.get("/mcp/tools")
def list_mcp_tools() -> List[dict]:
    """Return the catalog of available MCP tools."""
    return _TOOL_CATALOG


@router.get("/mcp/tool-calls", response_model=List[ToolCallLog])
def list_tool_calls(limit: int = 50) -> Any:
    """Return recent tool call log entries, most recent first."""
    if not _LOG_FILE.exists():
        return []
    content = _LOG_FILE.read_text(encoding="utf-8").strip()
    if not content:
        return []
    entries = []
    for line in reversed(content.splitlines()):
        if len(entries) >= limit:
            break
        try:
            entries.append(json.loads(line))
        except Exception:
            continue
    return entries
