from __future__ import annotations

import asyncio
import time
from typing import Any

from .tools import (
    ai_security_tools,
    api_tools,
    code_review_tools,
    command_tools,
    file_tools,
    malware_analysis_tools,
    network_tools,
    project_tools,
    report_tools,
    security_kb_tools,
    security_test_tools,
)

MCP_TOOL_DEFINITIONS: list[dict] = [
    # ── Network ──────────────────────────────────────────────────────────────
    {
        "name": "ping",
        "category": "network",
        "description": "Ping a target host (3 packets). Only loopback and scope-authorised targets.",
        "parameters": {
            "target": {"type": "string", "description": "Hostname or IP to ping (required)"},
        },
        "required": ["target"],
    },
    {
        "name": "dig",
        "category": "network",
        "description": "DNS lookup for a target. Only scope-authorised targets.",
        "parameters": {
            "target": {"type": "string", "description": "Domain or hostname to query (required)"},
            "record_type": {"type": "string", "description": "DNS record type, e.g. A, MX, TXT (default 'A')"},
        },
        "required": ["target"],
    },
    {
        "name": "whois",
        "category": "network",
        "description": "WHOIS lookup for a domain or IP. Only scope-authorised targets.",
        "parameters": {
            "target": {"type": "string", "description": "Domain or IP to look up (required)"},
        },
        "required": ["target"],
    },
    {
        "name": "nmap_basic",
        "category": "network",
        "description": "Basic nmap scan: nmap -Pn -T3 <target>. No scripts, no exploitation. Scope-gated.",
        "parameters": {
            "target": {"type": "string", "description": "IP or hostname to scan (required)"},
        },
        "required": ["target"],
    },
    {
        "name": "nmap_service",
        "category": "network",
        "description": "Service version detection: nmap -sV -T3 <target>. Scope-gated.",
        "parameters": {
            "target": {"type": "string", "description": "IP or hostname to scan (required)"},
        },
        "required": ["target"],
    },
    {
        "name": "nmap_top_ports",
        "category": "network",
        "description": "Top-N port scan: nmap --top-ports N -T3 <target>. Max 1000 ports. Scope-gated.",
        "parameters": {
            "target": {"type": "string", "description": "IP or hostname to scan (required)"},
            "count": {"type": "integer", "description": "Number of top ports to scan (default 100, max 1000)"},
        },
        "required": ["target"],
    },
    # ── File ─────────────────────────────────────────────────────────────────
    {
        "name": "list_files",
        "category": "file",
        "description": "List files in a directory within the Oyster project.",
        "parameters": {
            "path": {"type": "string", "description": "Relative path within project (default '.')"},
            "pattern": {"type": "string", "description": "Filename glob pattern (default '*')"},
        },
    },
    {
        "name": "read_file",
        "category": "file",
        "description": "Read file content. Restricted to project root; .env values are redacted.",
        "parameters": {
            "path": {"type": "string", "description": "Relative path to file (required)"},
        },
        "required": ["path"],
    },
    {
        "name": "write_file",
        "category": "file",
        "description": "Write (or overwrite) a file within the project root. Sensitive paths are blocked.",
        "parameters": {
            "path": {"type": "string", "description": "Relative path to file (required)"},
            "content": {"type": "string", "description": "Text content to write (required)"},
        },
        "required": ["path", "content"],
    },
    {
        "name": "search_files",
        "category": "file",
        "description": "Full-text search across project files.",
        "parameters": {
            "query": {"type": "string", "description": "Text to search for (required)"},
            "path": {"type": "string", "description": "Directory to search in (default '.')"},
            "file_pattern": {"type": "string", "description": "Filename glob, e.g. '*.py' (default '*')"},
        },
        "required": ["query"],
    },
    {
        "name": "inspect_project",
        "category": "file",
        "description": "Directory tree of the project (max depth 3, noise dirs excluded).",
        "parameters": {
            "path": {"type": "string", "description": "Sub-path to inspect (default '.')"},
        },
    },
    # ── Project ───────────────────────────────────────────────────────────────
    {
        "name": "inspect_fastapi_routes",
        "category": "project",
        "description": "Extract all FastAPI route declarations from main.py and mcp_server/server.py.",
        "parameters": {},
    },
    {
        "name": "inspect_nextjs_routes",
        "category": "project",
        "description": "List all Next.js page routes from the frontend app directory.",
        "parameters": {},
    },
    {
        "name": "run_frontend_build",
        "category": "project",
        "description": "Run npm run build in the frontend directory.",
        "parameters": {},
    },
    {
        "name": "run_backend_import_check",
        "category": "project",
        "description": "Check backend imports cleanly (python -c 'import main').",
        "parameters": {},
    },
    {
        "name": "run_safe_command",
        "category": "project",
        "description": (
            "Run an allowlisted shell command. "
            "Allowed: ls, pwd, cat, grep, find, npm run build, npm test, python -m pytest. "
            "Blocked: rm, sudo, curl, wget, chmod, ssh, and any shell metacharacters."
        ),
        "parameters": {
            "command": {"type": "string", "description": "Command string to run (required)"},
            "cwd": {"type": "string", "description": "Working directory relative to project root (default '.')"},
        },
        "required": ["command"],
    },
    # ── Security KB ───────────────────────────────────────────────────────────
    {
        "name": "search_security_kb",
        "category": "security_kb",
        "description": "Semantic search across uploaded knowledge-base documents (RAG).",
        "parameters": {
            "query": {"type": "string", "description": "Search query (required)"},
            "top_k": {"type": "integer", "description": "Max results to return (default 5)"},
        },
        "required": ["query"],
    },
    {
        "name": "get_security_context",
        "category": "security_kb",
        "description": "Retrieve relevant security context and related documents for a topic.",
        "parameters": {
            "topic": {"type": "string", "description": "Security topic to look up (required)"},
            "top_k": {"type": "integer", "description": "Max documents to retrieve (default 3)"},
        },
        "required": ["topic"],
    },
    # ── API Inspection ────────────────────────────────────────────────────────
    {
        "name": "http_probe",
        "category": "api",
        "description": "Send an HTTP request to a scoped URL and return status, headers, and body preview.",
        "parameters": {
            "url": {"type": "string", "description": "Target URL (required)"},
            "method": {"type": "string", "description": "HTTP method: GET|POST|PUT|DELETE (default GET)"},
            "headers": {"type": "object", "description": "Extra request headers (optional)"},
            "body": {"type": "string", "description": "Request body string (optional)"},
        },
        "required": ["url"],
    },
    {
        "name": "tech_stack_detect",
        "category": "api",
        "description": "Detect server, framework, and tech stack from HTTP response headers and body.",
        "parameters": {
            "url": {"type": "string", "description": "Target URL (required)"},
        },
        "required": ["url"],
    },
    {
        "name": "discover_api_routes",
        "category": "api",
        "description": "Probe common API paths on a base URL to discover exposed endpoints.",
        "parameters": {
            "base_url": {"type": "string", "description": "Base URL to probe (required)"},
        },
        "required": ["base_url"],
    },
    # ── Security Testing ──────────────────────────────────────────────────────
    {
        "name": "check_security_headers",
        "category": "security_test",
        "description": "Check for missing or misconfigured HTTP security headers (HSTS, CSP, X-Frame-Options, etc.).",
        "parameters": {
            "url": {"type": "string", "description": "Target URL (required)"},
        },
        "required": ["url"],
    },
    {
        "name": "check_cors_policy",
        "category": "security_test",
        "description": "Test CORS policy for misconfiguration — reflected origins and credential leakage.",
        "parameters": {
            "url": {"type": "string", "description": "Target URL (required)"},
        },
        "required": ["url"],
    },
    {
        "name": "detect_error_disclosure",
        "category": "security_test",
        "description": "Probe for verbose error messages, stack traces, or path disclosure in error responses.",
        "parameters": {
            "url": {"type": "string", "description": "Target URL (required)"},
        },
        "required": ["url"],
    },
    {
        "name": "test_auth_bypass",
        "category": "security_test",
        "description": "Attempt common authentication bypass techniques (missing token, role headers, forwarded-for).",
        "parameters": {
            "url": {"type": "string", "description": "Target URL (required)"},
            "method": {"type": "string", "description": "HTTP method (default GET)"},
        },
        "required": ["url"],
    },
    {
        "name": "test_upload_validation",
        "category": "security_test",
        "description": "Test file upload endpoint for insufficient content-type / extension validation.",
        "parameters": {
            "url": {"type": "string", "description": "Upload endpoint URL (required)"},
        },
        "required": ["url"],
    },
    {
        "name": "test_sqli_reflection",
        "category": "security_test",
        "description": "Test a URL parameter for SQL error signatures (error-based SQLi detection).",
        "parameters": {
            "url": {"type": "string", "description": "Target URL (required)"},
            "param": {"type": "string", "description": "Query parameter to test (default 'q')"},
        },
        "required": ["url"],
    },
    {
        "name": "test_xss_reflection",
        "category": "security_test",
        "description": "Test a URL parameter for reflected XSS (unencoded payload in response).",
        "parameters": {
            "url": {"type": "string", "description": "Target URL (required)"},
            "param": {"type": "string", "description": "Query parameter to test (default 'q')"},
        },
        "required": ["url"],
    },
    {
        "name": "check_ssrf_indicators",
        "category": "security_test",
        "description": "Probe common URL parameters for SSRF by checking for internal metadata leakage.",
        "parameters": {
            "url": {"type": "string", "description": "Target URL (required)"},
        },
        "required": ["url"],
    },
    # ── Code Review ───────────────────────────────────────────────────────────
    {
        "name": "secrets_scan",
        "category": "code_review",
        "description": "Scan project files for hardcoded secrets: API keys, tokens, passwords, connection strings.",
        "parameters": {
            "path": {"type": "string", "description": "Project-relative path to scan (default '.')"},
        },
    },
    {
        "name": "dependency_audit",
        "category": "code_review",
        "description": "Find requirements.txt and package.json and output commands to run CVE audits.",
        "parameters": {
            "path": {"type": "string", "description": "Project-relative path (default '.')"},
        },
    },
    {
        "name": "code_security_patterns",
        "category": "code_review",
        "description": "Static analysis for dangerous code patterns: eval, shell injection, SQLi, pickle, etc.",
        "parameters": {
            "path": {"type": "string", "description": "Project-relative path to scan (default '.')"},
            "language": {"type": "string", "description": "Language filter: auto|python|javascript (default auto)"},
        },
    },
    # ── AI Security ───────────────────────────────────────────────────────────
    {
        "name": "test_prompt_injection",
        "category": "ai_security",
        "description": "Send prompt injection payloads to an AI endpoint and detect if they triggered unsafe behavior.",
        "parameters": {
            "endpoint": {"type": "string", "description": "AI endpoint URL to test (required)"},
            "payload_category": {"type": "string", "description": "Payload set: basic|indirect|extraction (default basic)"},
        },
        "required": ["endpoint"],
    },
    {
        "name": "test_jailbreak",
        "category": "ai_security",
        "description": "Test a local Ollama model's resistance to jailbreak payloads.",
        "parameters": {
            "model": {"type": "string", "description": "Ollama model key (default 'dolphin3')"},
            "payload_category": {"type": "string", "description": "Payload set: basic|roleplay (default basic)"},
        },
    },
    {
        "name": "scan_model_output",
        "category": "ai_security",
        "description": "Scan LLM output text for unsafe content: credentials, PII, injection markers, harmful content.",
        "parameters": {
            "text": {"type": "string", "description": "Model output text to scan (required)"},
        },
        "required": ["text"],
    },
    {
        "name": "test_rag_leakage",
        "category": "ai_security",
        "description": "Test a RAG endpoint for document leakage or verbatim disclosure of stored content.",
        "parameters": {
            "endpoint": {"type": "string", "description": "RAG endpoint URL (required)"},
            "custom_query": {"type": "string", "description": "Additional custom test query (optional)"},
        },
        "required": ["endpoint"],
    },
    # ── Malware Analysis / Defensive ──────────────────────────────────────────
    {
        "name": "extract_iocs",
        "category": "malware_analysis",
        "description": "Extract IOCs from text: IPs, domains, URLs, emails, file hashes, CVEs, registry keys.",
        "parameters": {
            "text": {"type": "string", "description": "Text to extract IOCs from (required)"},
        },
        "required": ["text"],
    },
    {
        "name": "attck_technique_lookup",
        "category": "malware_analysis",
        "description": "Look up MITRE ATT&CK technique by ID (e.g. T1190) or keyword.",
        "parameters": {
            "query": {"type": "string", "description": "Technique ID or keyword (required)"},
        },
        "required": ["query"],
    },
    {
        "name": "sigma_match",
        "category": "malware_analysis",
        "description": "Match log text against Sigma-like detection rules (PowerShell, lateral movement, ransomware, etc.).",
        "parameters": {
            "log_text": {"type": "string", "description": "Log or event text to analyze (required)"},
            "rule_name": {"type": "string", "description": "Specific rule name filter, or 'all' (default 'all')"},
        },
        "required": ["log_text"],
    },
    {
        "name": "yara_pattern_match",
        "category": "malware_analysis",
        "description": "Match text against YARA-like behavioral rules: encoded PE, reverse shell, cryptominer, C2.",
        "parameters": {
            "text": {"type": "string", "description": "Text or code to analyze (required)"},
        },
        "required": ["text"],
    },
    {
        "name": "parse_incident_timeline",
        "category": "malware_analysis",
        "description": "Extract timestamped events, IOCs, and Sigma matches from incident report text.",
        "parameters": {
            "text": {"type": "string", "description": "Incident report or log text (required)"},
        },
        "required": ["text"],
    },
    {
        "name": "sandbox_report_summary",
        "category": "malware_analysis",
        "description": "Parse a sandbox behavioral report JSON and extract IOCs, YARA hits, and verdict.",
        "parameters": {
            "report_json": {"type": "string", "description": "Sandbox report as JSON string (required)"},
        },
        "required": ["report_json"],
    },
    # ── Report ────────────────────────────────────────────────────────────────
    {
        "name": "create_finding",
        "category": "report",
        "description": "Log a new security finding to the evidence store.",
        "parameters": {
            "title": {"type": "string", "description": "Short finding title (required)"},
            "severity": {"type": "string", "description": "critical | high | medium | low | info (required)"},
            "endpoint": {"type": "string", "description": "Affected endpoint or component (required)"},
            "description": {"type": "string", "description": "Detailed description (required)"},
            "steps_to_reproduce": {"type": "string", "description": "Steps to reproduce"},
            "recommended_fix": {"type": "string", "description": "Recommended remediation"},
        },
        "required": ["title", "severity", "endpoint", "description"],
    },
    {
        "name": "list_findings",
        "category": "report",
        "description": "Return all logged security findings from the evidence store.",
        "parameters": {},
    },
    {
        "name": "generate_report",
        "category": "report",
        "description": "Generate a professional penetration test report from logged findings.",
        "parameters": {
            "engagement_name": {"type": "string", "description": "Engagement name (required)"},
            "model": {"type": "string", "description": "LLM model key (default 'dolphin3')"},
        },
        "required": ["engagement_name"],
    },
    {
        "name": "score_risk",
        "category": "report",
        "description": "Calculate a CVSS-lite risk score from severity, exploitability, attack vector, and impact.",
        "parameters": {
            "severity": {"type": "string", "description": "critical|high|medium|low|info (required)"},
            "exploitability": {"type": "string", "description": "easy|medium|hard (default medium)"},
            "attack_vector": {"type": "string", "description": "network|adjacent|local|physical (default network)"},
            "impact": {"type": "string", "description": "high|medium|low|none (default medium)"},
        },
        "required": ["severity"],
    },
    {
        "name": "generate_executive_summary",
        "category": "report",
        "description": "Generate a non-technical executive summary of all logged findings via LLM.",
        "parameters": {
            "engagement_name": {"type": "string", "description": "Engagement name (required)"},
            "model": {"type": "string", "description": "LLM model key (default 'dolphin3')"},
        },
        "required": ["engagement_name"],
    },
    {
        "name": "remediation_guidance",
        "category": "report",
        "description": "Generate specific remediation guidance for a vulnerability type via LLM.",
        "parameters": {
            "finding_type": {"type": "string", "description": "Vulnerability type, e.g. 'SQL Injection' (required)"},
            "context": {"type": "string", "description": "Additional context about the finding (optional)"},
            "model": {"type": "string", "description": "LLM model key (default 'dolphin3')"},
        },
        "required": ["finding_type"],
    },
]

_TOOL_NAMES: frozenset[str] = frozenset(d["name"] for d in MCP_TOOL_DEFINITIONS)

_SYNC_TOOLS: dict[str, Any] = {
    # Network
    "ping": network_tools.ping,
    "dig": network_tools.dig,
    "whois": network_tools.whois,
    "nmap_basic": network_tools.nmap_basic,
    "nmap_service": network_tools.nmap_service,
    "nmap_top_ports": network_tools.nmap_top_ports,
    # File
    "list_files": file_tools.list_files,
    "read_file": file_tools.read_file,
    "write_file": file_tools.write_file,
    "search_files": file_tools.search_files,
    "inspect_project": file_tools.inspect_project,
    # Project
    "inspect_fastapi_routes": project_tools.inspect_fastapi_routes,
    "inspect_nextjs_routes": project_tools.inspect_nextjs_routes,
    "run_frontend_build": project_tools.run_frontend_build,
    "run_backend_import_check": project_tools.run_backend_import_check,
    "run_safe_command": command_tools.run_safe_command,
    # Report
    "create_finding": report_tools.create_finding,
    "list_findings": report_tools.list_findings,
    "score_risk": report_tools.score_risk,
    # Code Review (sync — file I/O + regex)
    "secrets_scan": code_review_tools.secrets_scan,
    "dependency_audit": code_review_tools.dependency_audit,
    "code_security_patterns": code_review_tools.code_security_patterns,
    # AI Security (sync)
    "scan_model_output": ai_security_tools.scan_model_output,
    # Malware Analysis (sync — regex/pattern matching)
    "extract_iocs": malware_analysis_tools.extract_iocs,
    "attck_technique_lookup": malware_analysis_tools.attck_technique_lookup,
    "sigma_match": malware_analysis_tools.sigma_match,
    "yara_pattern_match": malware_analysis_tools.yara_pattern_match,
    "parse_incident_timeline": malware_analysis_tools.parse_incident_timeline,
    "sandbox_report_summary": malware_analysis_tools.sandbox_report_summary,
}

_ASYNC_TOOLS: dict[str, Any] = {
    # Security KB
    "search_security_kb": security_kb_tools.search_security_kb,
    "get_security_context": security_kb_tools.get_security_context,
    # Report
    "generate_report": report_tools.generate_report,
    "generate_executive_summary": report_tools.generate_executive_summary,
    "remediation_guidance": report_tools.remediation_guidance,
    # API Inspection (async HTTP)
    "http_probe": api_tools.http_probe,
    "tech_stack_detect": api_tools.tech_stack_detect,
    "discover_api_routes": api_tools.discover_api_routes,
    # Security Testing (async HTTP)
    "check_security_headers": security_test_tools.check_security_headers,
    "check_cors_policy": security_test_tools.check_cors_policy,
    "detect_error_disclosure": security_test_tools.detect_error_disclosure,
    "test_auth_bypass": security_test_tools.test_auth_bypass,
    "test_upload_validation": security_test_tools.test_upload_validation,
    "test_sqli_reflection": security_test_tools.test_sqli_reflection,
    "test_xss_reflection": security_test_tools.test_xss_reflection,
    "check_ssrf_indicators": security_test_tools.check_ssrf_indicators,
    # AI Security (async — LLM / HTTP)
    "test_prompt_injection": ai_security_tools.test_prompt_injection,
    "test_jailbreak": ai_security_tools.test_jailbreak,
    "test_rag_leakage": ai_security_tools.test_rag_leakage,
}


async def call_tool(name: str, arguments: dict) -> tuple[dict, float]:
    """Dispatch a tool call. Returns (result_dict, duration_ms)."""
    if name not in _TOOL_NAMES:
        return (
            {"error": f"Unknown tool '{name}'. Available: {', '.join(sorted(_TOOL_NAMES))}"},
            0.0,
        )
    t0 = time.perf_counter()
    try:
        if name in _ASYNC_TOOLS:
            result = await _ASYNC_TOOLS[name](**arguments)
        else:
            result = await asyncio.to_thread(_SYNC_TOOLS[name], **arguments)
    except TypeError as exc:
        result = {"error": f"Invalid arguments for tool '{name}': {exc}"}
    except Exception as exc:
        result = {"error": f"Tool '{name}' raised an exception: {exc}"}
    duration_ms = (time.perf_counter() - t0) * 1000
    return result, duration_ms
