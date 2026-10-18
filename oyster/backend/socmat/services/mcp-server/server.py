"""
SOC Copilot Workbench — MCP Tool Server (Phase 14)

Exposes 12 safe defensive SOC analysis tools via the Model Context Protocol.
Transport: stdio — compatible with Claude Desktop, Cursor, VS Code, and any
MCP-aware AI client.

Security restrictions (enforced here and in the FastAPI backend):
  - No destructive actions — no delete or wipe endpoints exposed
  - No arbitrary shell command execution
  - No direct filesystem or database access — all I/O through FastAPI
  - No offensive analysis capabilities

Environment variables:
  MCP_BACKEND_URL  — FastAPI backend URL  (default: http://localhost:8000)
  MCP_LOG_FILE     — Tool call log path   (default: ./mcp_tool_calls.jsonl)

Run:
    cd services/mcp-server
    pip install -r requirements.txt
    python server.py
"""

from typing import Optional

from mcp.server.fastmcp import FastMCP

import client as _c

mcp = FastMCP(
    "SOC Copilot Workbench",
    description=(
        "Defensive SOC analysis tools for investigation assistance. "
        "All tools operate on stored case data. "
        "No offensive capabilities or arbitrary command execution."
    ),
)


# ── Read-only tools ──────────────────────────────────────────────────────────────

@mcp.tool()
def list_cases() -> dict:
    """List all investigation cases with their severity, status, and metadata."""
    try:
        result = _c.api_get("/cases")
        _c.log_tool_call("list_cases", None, True)
        return {"cases": result}
    except Exception as exc:
        _c.log_tool_call("list_cases", None, False, str(exc))
        return {"error": str(exc)}


@mcp.tool()
def get_case_summary(case_id: int) -> dict:
    """
    Return a structured summary of a case including case details, correlated
    findings, and MITRE ATT&CK mappings. Use list_cases first to find case IDs.
    """
    try:
        case = _c.api_get(f"/cases/{case_id}")
        correlations = _c.api_get(f"/cases/{case_id}/correlate")
        mitre = _c.api_get(f"/cases/{case_id}/mitre/map")
        result = {
            "case": case,
            "correlated_findings": correlations,
            "mitre_mappings": mitre,
        }
        _c.log_tool_call("get_case_summary", case_id, True)
        return result
    except Exception as exc:
        _c.log_tool_call("get_case_summary", case_id, False, str(exc))
        return {"error": str(exc)}


@mcp.tool()
def list_case_evidence(case_id: int) -> dict:
    """
    List all evidence files uploaded to a case. Returns file metadata including
    evidence IDs needed by analysis tools.
    """
    try:
        result = _c.api_get(f"/cases/{case_id}/evidence")
        _c.log_tool_call("list_case_evidence", case_id, True)
        return {"evidence": result}
    except Exception as exc:
        _c.log_tool_call("list_case_evidence", case_id, False, str(exc))
        return {"error": str(exc)}


@mcp.tool()
def get_case_timeline(case_id: int) -> dict:
    """Return the full chronological investigation timeline for a case."""
    try:
        result = _c.api_get(f"/cases/{case_id}/timeline")
        _c.log_tool_call("get_case_timeline", case_id, True)
        return {"timeline": result}
    except Exception as exc:
        _c.log_tool_call("get_case_timeline", case_id, False, str(exc))
        return {"error": str(exc)}


# ── Analysis tools ───────────────────────────────────────────────────────────────

@mcp.tool()
def run_windows_log_analysis(case_id: int, evidence_id: int) -> dict:
    """
    Run Windows/Sysmon event log analysis on an uploaded evidence file.
    The file is analyzed statically — it is never executed.
    Use list_case_evidence to obtain a valid evidence_id first.
    """
    try:
        result = _c.api_post(
            f"/cases/{case_id}/analyze/windows-logs",
            params={"evidence_id": evidence_id},
        )
        _c.log_tool_call("run_windows_log_analysis", case_id, True)
        return result
    except Exception as exc:
        _c.log_tool_call("run_windows_log_analysis", case_id, False, str(exc))
        return {"error": str(exc)}


@mcp.tool()
def run_suricata_analysis(case_id: int, evidence_id: int) -> dict:
    """
    Run Suricata IDS/IPS alert log analysis on an uploaded evidence file.
    The file is analyzed statically — it is never executed.
    Use list_case_evidence to obtain a valid evidence_id first.
    """
    try:
        result = _c.api_post(
            f"/cases/{case_id}/analyze/suricata",
            params={"evidence_id": evidence_id},
        )
        _c.log_tool_call("run_suricata_analysis", case_id, True)
        return result
    except Exception as exc:
        _c.log_tool_call("run_suricata_analysis", case_id, False, str(exc))
        return {"error": str(exc)}


@mcp.tool()
def run_zeek_analysis(case_id: int, evidence_id: int) -> dict:
    """
    Run Zeek network log analysis on an uploaded evidence file.
    The file is analyzed statically — it is never executed.
    Use list_case_evidence to obtain a valid evidence_id first.
    """
    try:
        result = _c.api_post(
            f"/cases/{case_id}/analyze/zeek",
            body={"evidence_id": evidence_id},
        )
        _c.log_tool_call("run_zeek_analysis", case_id, True)
        return result
    except Exception as exc:
        _c.log_tool_call("run_zeek_analysis", case_id, False, str(exc))
        return {"error": str(exc)}


@mcp.tool()
def run_sigma_rules(case_id: int) -> dict:
    """
    Run all Sigma detection rules attached to this case against its normalized
    events. Attach rules first via the Sigma Rules UI before calling this tool.
    """
    try:
        result = _c.api_post(f"/cases/{case_id}/sigma/run")
        _c.log_tool_call("run_sigma_rules", case_id, True)
        return result
    except Exception as exc:
        _c.log_tool_call("run_sigma_rules", case_id, False, str(exc))
        return {"error": str(exc)}


@mcp.tool()
def run_yara_scan(case_id: int, evidence_id: int) -> dict:
    """
    Run YARA static malware triage on an uploaded evidence file.
    The file is analyzed statically — it is never executed.
    Use list_case_evidence to obtain a valid evidence_id first.
    """
    try:
        result = _c.api_post(
            f"/cases/{case_id}/analyze/yara",
            body={"evidence_id": evidence_id},
        )
        _c.log_tool_call("run_yara_scan", case_id, True)
        return result
    except Exception as exc:
        _c.log_tool_call("run_yara_scan", case_id, False, str(exc))
        return {"error": str(exc)}


@mcp.tool()
def run_correlation(case_id: int) -> dict:
    """
    Run the investigation correlation engine across all analysis modules.
    Identifies cross-module patterns and multi-stage attack indicators.
    Run analysis modules first before correlating.
    """
    try:
        result = _c.api_post(f"/cases/{case_id}/correlate")
        _c.log_tool_call("run_correlation", case_id, True)
        return {"correlated_findings": result}
    except Exception as exc:
        _c.log_tool_call("run_correlation", case_id, False, str(exc))
        return {"error": str(exc)}


@mcp.tool()
def run_mitre_mapping(case_id: int) -> dict:
    """
    Map all case findings to MITRE ATT&CK techniques and tactics.
    Returns technique IDs, names, tactic categories, and confidence scores.
    """
    try:
        result = _c.api_post(f"/cases/{case_id}/mitre/map")
        _c.log_tool_call("run_mitre_mapping", case_id, True)
        return {"mitre_mappings": result}
    except Exception as exc:
        _c.log_tool_call("run_mitre_mapping", case_id, False, str(exc))
        return {"error": str(exc)}


@mcp.tool()
def generate_incident_report(case_id: int) -> dict:
    """
    Generate a structured Markdown security incident report for a case.
    The report covers all analysis modules with a complete findings summary.
    Returns report metadata including file path and generation timestamp.
    """
    try:
        result = _c.api_post(f"/cases/{case_id}/report/generate")
        _c.log_tool_call("generate_incident_report", case_id, True)
        return result
    except Exception as exc:
        _c.log_tool_call("generate_incident_report", case_id, False, str(exc))
        return {"error": str(exc)}


# ── Splunk tools ─────────────────────────────────────────────────────────────────

@mcp.tool()
def check_splunk_connection() -> dict:
    """
    Check whether the live Splunk connector is configured and reachable.
    Call this before running any live Splunk query to verify SPLUNK_URL and
    SPLUNK_TOKEN are set and the instance is responding.
    """
    try:
        result = _c.api_get("/splunk/live/status")
        _c.log_tool_call("check_splunk_connection", None, True)
        return result
    except Exception as exc:
        _c.log_tool_call("check_splunk_connection", None, False, str(exc))
        return {"error": str(exc)}


@mcp.tool()
def run_splunk_query(
    spl_query: str,
    earliest_time: str = "-24h",
    latest_time: str = "now",
    max_results: int = 100,
    case_id: Optional[int] = None,
) -> dict:
    """
    Run a free-form SPL query against a live Splunk instance.
    Requires SPLUNK_URL and SPLUNK_TOKEN environment variables.
    Results are capped at 500 rows; up to 20 sample rows are stored per query.
    Optionally associate the query with a case by providing case_id.
    Call check_splunk_connection first to verify the connector is available.
    """
    try:
        body: dict = {
            "spl_query": spl_query,
            "earliest_time": earliest_time,
            "latest_time": latest_time,
            "max_results": max_results,
        }
        if case_id is not None:
            body["case_id"] = case_id
        result = _c.api_post("/splunk/live/search", body=body)
        _c.log_tool_call("run_splunk_query", case_id, True)
        return result
    except Exception as exc:
        _c.log_tool_call("run_splunk_query", case_id, False, str(exc))
        return {"error": str(exc)}


@mcp.tool()
def run_splunk_template(
    template_id: str,
    earliest_time: str = "-24h",
    latest_time: str = "now",
    max_results: int = 100,
    case_id: Optional[int] = None,
) -> dict:
    """
    Run a pre-approved SPL template against a live Splunk instance.
    Available template IDs: failed_logins, success_after_failures,
    powershell_encoded, new_service, suspicious_process,
    rare_parent_child, outbound_connections.
    Call check_splunk_connection first to verify the connector is available.
    """
    try:
        body: dict = {
            "earliest_time": earliest_time,
            "latest_time": latest_time,
            "max_results": max_results,
        }
        if case_id is not None:
            body["case_id"] = case_id
        result = _c.api_post(f"/splunk/live/templates/{template_id}/run", body=body)
        _c.log_tool_call("run_splunk_template", case_id, True)
        return result
    except Exception as exc:
        _c.log_tool_call("run_splunk_template", case_id, False, str(exc))
        return {"error": str(exc)}


@mcp.tool()
def list_splunk_queries(case_id: Optional[int] = None) -> dict:
    """
    List stored Splunk live query history, newest first (up to 100 entries).
    Optionally filter by case_id to see only queries tied to a specific case.
    """
    try:
        path = "/splunk/live/queries"
        if case_id is not None:
            path += f"?case_id={case_id}"
        result = _c.api_get(path)
        _c.log_tool_call("list_splunk_queries", case_id, True)
        return {"queries": result}
    except Exception as exc:
        _c.log_tool_call("list_splunk_queries", case_id, False, str(exc))
        return {"error": str(exc)}


@mcp.tool()
def analyze_splunk_export(case_id: int, evidence_id: int) -> dict:
    """
    Parse and analyze an uploaded Splunk CSV or JSON export file.
    Normalizes 11 standard Splunk fields and adds high-signal events to the
    case timeline. Use list_case_evidence to find a valid evidence_id for a
    Splunk export file.
    """
    try:
        result = _c.api_post(
            f"/cases/{case_id}/analyze/splunk-export",
            params={"evidence_id": evidence_id},
        )
        _c.log_tool_call("analyze_splunk_export", case_id, True)
        return result
    except Exception as exc:
        _c.log_tool_call("analyze_splunk_export", case_id, False, str(exc))
        return {"error": str(exc)}


# ── Elastic tools ────────────────────────────────────────────────────────────────

@mcp.tool()
def check_elastic_connection() -> dict:
    """
    Check whether the live Elasticsearch connector is configured and reachable.
    Call this before running any live ES|QL query to verify ELASTIC_URL and
    ELASTIC_API_KEY are set and the cluster is responding.
    """
    try:
        result = _c.api_get("/elastic/live/status")
        _c.log_tool_call("check_elastic_connection", None, True)
        return result
    except Exception as exc:
        _c.log_tool_call("check_elastic_connection", None, False, str(exc))
        return {"error": str(exc)}


@mcp.tool()
def run_elastic_query(
    esql_query: str,
    max_results: int = 50,
    case_id: Optional[int] = None,
) -> dict:
    """
    Run a free-form ES|QL query against a live Elasticsearch instance (8.11+).
    Requires ELASTIC_URL and ELASTIC_API_KEY environment variables.
    Results are capped at 500 rows. Optionally associate with a case via case_id.
    Call check_elastic_connection first to verify the connector is available.
    Example: FROM logs-* | WHERE event.category == "authentication" | LIMIT 50
    """
    try:
        body: dict = {"esql_query": esql_query, "max_results": max_results}
        if case_id is not None:
            body["case_id"] = case_id
        result = _c.api_post("/elastic/live/search", body=body)
        _c.log_tool_call("run_elastic_query", case_id, True)
        return result
    except Exception as exc:
        _c.log_tool_call("run_elastic_query", case_id, False, str(exc))
        return {"error": str(exc)}


@mcp.tool()
def run_elastic_template(
    template_id: str,
    max_results: int = 50,
    case_id: Optional[int] = None,
) -> dict:
    """
    Run a pre-approved ES|QL hunt template against a live Elasticsearch instance.
    Available template IDs: encoded_powershell, suspicious_child_process,
    new_service_creation, rare_outbound_destination, dns_tunneling,
    auth_failure_then_success, suspicious_script_interpreter.
    Call check_elastic_connection first to verify the connector is available.
    """
    try:
        body: dict = {"max_results": max_results}
        if case_id is not None:
            body["case_id"] = case_id
        result = _c.api_post(f"/elastic/live/templates/{template_id}/run", body=body)
        _c.log_tool_call("run_elastic_template", case_id, True)
        return result
    except Exception as exc:
        _c.log_tool_call("run_elastic_template", case_id, False, str(exc))
        return {"error": str(exc)}


@mcp.tool()
def list_elastic_queries(case_id: Optional[int] = None) -> dict:
    """
    List stored Elasticsearch live query history, newest first (up to 100 entries).
    Optionally filter by case_id to see only queries tied to a specific case.
    """
    try:
        path = "/elastic/live/queries"
        if case_id is not None:
            path += f"?case_id={case_id}"
        result = _c.api_get(path)
        _c.log_tool_call("list_elastic_queries", case_id, True)
        return {"queries": result}
    except Exception as exc:
        _c.log_tool_call("list_elastic_queries", case_id, False, str(exc))
        return {"error": str(exc)}


@mcp.tool()
def analyze_elastic_export(case_id: int, evidence_id: int) -> dict:
    """
    Parse and analyze an uploaded Kibana NDJSON or Elastic export file.
    Normalizes ECS fields and adds high-signal events to the case timeline.
    Use list_case_evidence to find a valid evidence_id for an Elastic export file.
    """
    try:
        result = _c.api_post(
            f"/cases/{case_id}/analyze/elastic-export",
            params={"evidence_id": evidence_id},
        )
        _c.log_tool_call("analyze_elastic_export", case_id, True)
        return result
    except Exception as exc:
        _c.log_tool_call("analyze_elastic_export", case_id, False, str(exc))
        return {"error": str(exc)}


if __name__ == "__main__":
    mcp.run()
