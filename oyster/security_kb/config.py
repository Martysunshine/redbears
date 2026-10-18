"""Central configuration for the security KB pipeline."""

from __future__ import annotations

import os
from pathlib import Path

from dotenv import load_dotenv

load_dotenv()

BASE_DIR = Path(__file__).parent
DATA_DIR = BASE_DIR / "data"
RAW_DIR = DATA_DIR / "raw"
VECTOR_STORE_DIR = DATA_DIR / "vector_store"

# ── embedding / chunking ──────────────────────────────────────────────────────
EMBEDDING_MODEL: str = os.getenv("EMBEDDING_MODEL", "all-MiniLM-L6-v2")
COLLECTION_NAME: str = os.getenv("COLLECTION_NAME", "security_kb")
CHUNK_SIZE: int = int(os.getenv("CHUNK_SIZE", "1000"))
CHUNK_OVERLAP: int = int(os.getenv("CHUNK_OVERLAP", "200"))
BATCH_SIZE: int = int(os.getenv("BATCH_SIZE", "64"))   # docs per embed batch

# ── raw data categories → directories ────────────────────────────────────────
CATEGORIES: dict[str, Path] = {
    "owasp":       RAW_DIR / "owasp",
    "tools":       RAW_DIR / "tools",
    "labs":        RAW_DIR / "labs",
    "writeups":    RAW_DIR / "writeups",
    "ai_security": RAW_DIR / "ai_security",
}

# ── repos to clone (name → git URL) ──────────────────────────────────────────
OWASP_REPOS: dict[str, str] = {
    "wstg":            "https://github.com/OWASP/wstg.git",
    "CheatSheetSeries":"https://github.com/OWASP/CheatSheetSeries.git",
    "API-Security":    "https://github.com/OWASP/API-Security.git",
    "Top10":           "https://github.com/OWASP/Top10.git",
    "www-project-top-10-for-large-language-model-applications":
                       "https://github.com/OWASP/www-project-top-10-for-large-language-model-applications.git",
}

TOOL_REPOS: dict[str, str] = {
    "nuclei-templates": "https://github.com/projectdiscovery/nuclei-templates.git",
    "nmap-nse-scripts":  "https://github.com/nmap/nmap.git",
    "ffuf":              "https://github.com/ffuf/ffuf.git",
    "amass":             "https://github.com/owasp-amass/amass.git",
    "subfinder":         "https://github.com/projectdiscovery/subfinder.git",
    "httpx-tool":        "https://github.com/projectdiscovery/httpx.git",
    "katana":            "https://github.com/projectdiscovery/katana.git",
    "trivy":             "https://github.com/aquasecurity/trivy.git",
}

LAB_REPOS: dict[str, str] = {
    "juice-shop": "https://github.com/juice-shop/juice-shop.git",
    "WebGoat":    "https://github.com/WebGoat/WebGoat.git",
    "DVWA":       "https://github.com/digininja/DVWA.git",
}

PAYLOAD_REPOS: dict[str, str] = {
    "PayloadsAllTheThings": "https://github.com/swisskyrepo/PayloadsAllTheThings.git",
    "SecLists":             "https://github.com/danielmiessler/SecLists.git",
    "Awesome-Pentest":      "https://github.com/enaqx/awesome-pentest.git",
}

AI_SECURITY_REPOS: dict[str, str] = {
    "garak":             "https://github.com/leondz/garak.git",
    "promptfoo":         "https://github.com/promptfoo/promptfoo.git",
    "Awesome-AI-Security":"https://github.com/DeepSpaceHarbor/Awesome-AI-Security.git",
}
