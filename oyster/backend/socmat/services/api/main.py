import logging
import os
from contextlib import asynccontextmanager
from dotenv import load_dotenv
load_dotenv()  # load .env when running locally (no-op in Docker where env vars are injected)

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from socmat.services.api.database import init_db
from socmat.services.api.routers import health, cases, evidence, timeline, windows_logs, suricata, sigma, yara as yara_router, zeek as zeek_router, correlation as correlation_router, mitre as mitre_router, reports as reports_router, ai_assistant as ai_assistant_router, mcp_status as mcp_status_router, splunk as splunk_router, splunk_live as splunk_live_router, elastic as elastic_router, elastic_live as elastic_live_router, dashboard as dashboard_router, pcap as pcap_router, rule_authoring as rule_authoring_router, playbooks as playbooks_router, analyst_notes as analyst_notes_router, iocs as iocs_router, graph as graph_router, coverage as coverage_router, dispositions as dispositions_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    from socmat.integrations.yara.loader import load_yara_rules
    load_yara_rules()
    from socmat.services.api.playbook_seeds import seed_playbook_templates
    seed_playbook_templates()
    yield


# Mounted inside Oyster at /socmat/api, so the interactive docs and the OpenAPI
# schema — the whole route table plus the version string — were reachable by any
# signed-in account. Same rule as the host app (oyster/backend/main.py): off in
# production, on for local development.
_IS_PROD = os.environ.get("OYSTER_ENVIRONMENT", "").strip().lower() == "production"

app = FastAPI(
    title="SOC Copilot Workbench API",
    description="Local-first defensive SOC automation platform",
    version="0.33.0",
    lifespan=lifespan,
    docs_url=None if _IS_PROD else "/docs",
    redoc_url=None if _IS_PROD else "/redoc",
    openapi_url=None if _IS_PROD else "/openapi.json",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(Exception)
async def _unhandled_error_handler(request: Request, exc: Exception):
    """The body says only that we failed; the cause goes to the server log."""
    logging.getLogger("socmat").exception("unhandled %s %s", request.method, request.url.path)
    return JSONResponse(status_code=500, content={"detail": "Internal server error"})

app.include_router(health.router)
app.include_router(cases.router)
app.include_router(evidence.router)
app.include_router(timeline.router)
app.include_router(windows_logs.router)
app.include_router(suricata.router)
app.include_router(sigma.router)
app.include_router(yara_router.router)
app.include_router(zeek_router.router)
app.include_router(correlation_router.router)
app.include_router(mitre_router.router)
app.include_router(reports_router.router)
app.include_router(ai_assistant_router.router)
app.include_router(mcp_status_router.router)
app.include_router(splunk_router.router)
app.include_router(splunk_live_router.router)
app.include_router(elastic_router.router)
app.include_router(elastic_live_router.router)
app.include_router(pcap_router.router)
app.include_router(rule_authoring_router.router)
app.include_router(playbooks_router.router)
app.include_router(analyst_notes_router.router)
app.include_router(iocs_router.router)
app.include_router(graph_router.router)
app.include_router(coverage_router.router)
app.include_router(dispositions_router.router)
app.include_router(dashboard_router.router)
