from __future__ import annotations

import json
import re
from pathlib import Path

_PROJECT_ROOT = Path(__file__).parents[3].resolve()
_SKIP_DIRS = {"__pycache__", "venv", "node_modules", ".next", ".git", "vector_db", ".cache"}
_MAX_FILE_SIZE = 512 * 1024

_SECRET_PATTERNS: dict[str, re.Pattern] = {
    "AWS Access Key": re.compile(r"AKIA[0-9A-Z]{16}"),
    "AWS Secret Key": re.compile(r"aws_secret_access_key\s*=\s*['\"][A-Za-z0-9/+=]{40}['\"]", re.I),
    "GitHub Token": re.compile(r"(ghp_|ghs_|gho_|github_pat_)[A-Za-z0-9_]{30,}"),
    "Generic API Key": re.compile(r"api[_-]?key\s*[=:]\s*['\"][A-Za-z0-9_\-]{20,}['\"]", re.I),
    "Generic Secret": re.compile(r"(?:secret|password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{8,}['\"]", re.I),
    "JWT Token": re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
    "Private Key Header": re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
    "Database URL": re.compile(r"(?:mongodb|postgresql|mysql|redis|amqp)://[^\s\"']+", re.I),
    "Slack Token": re.compile(r"xox[baprs]-[A-Za-z0-9\-]{20,}"),
    "Stripe Key": re.compile(r"sk_(?:live|test)_[A-Za-z0-9]{24,}"),
    "Credentials in URL": re.compile(r"(?:http|https|ftp)://[a-z0-9._-]+:[^@\s]+@", re.I),
    "OpenAI API Key": re.compile(r"sk-[A-Za-z0-9]{48}"),
    "Anthropic API Key": re.compile(r"sk-ant-[A-Za-z0-9\-_]{40,}"),
}

_FALSE_POSITIVE_MARKERS = {"PLACEHOLDER", "EXAMPLE", "YOUR_KEY", "INSERT_HERE", "CHANGEME", "REPLACE"}

_PYTHON_PATTERNS: list[dict] = [
    {"name": "eval() usage", "pattern": re.compile(r"\beval\s*\("), "severity": "high"},
    {"name": "exec() usage", "pattern": re.compile(r"\bexec\s*\("), "severity": "high"},
    {"name": "shell=True in subprocess", "pattern": re.compile(r"subprocess\.\w+\s*\([^)]*shell\s*=\s*True"), "severity": "critical"},
    {"name": "pickle deserialization", "pattern": re.compile(r"pickle\.(?:loads?|Unpickler)\s*\("), "severity": "high"},
    {"name": "yaml.load without Loader", "pattern": re.compile(r"yaml\.load\s*\([^,)]+\)(?!\s*,?\s*Loader)"), "severity": "high"},
    {"name": "SQL string formatting", "pattern": re.compile(r'(?:execute|query)\s*\(\s*(?:f["\']|["\'].*\%s|["\'].*\+)'), "severity": "high"},
    {"name": "os.system() call", "pattern": re.compile(r"\bos\.system\s*\("), "severity": "medium"},
    {"name": "Hardcoded DEBUG=True", "pattern": re.compile(r"\bDEBUG\s*=\s*True\b"), "severity": "medium"},
    {"name": "SSL verify=False", "pattern": re.compile(r"\bverify\s*=\s*False\b"), "severity": "medium"},
    {"name": "tempfile.mktemp (race condition)", "pattern": re.compile(r"\btempfile\.mktemp\s*\("), "severity": "medium"},
    {"name": "Dynamic __import__", "pattern": re.compile(r"\b__import__\s*\("), "severity": "high"},
    {"name": "marshal.loads", "pattern": re.compile(r"\bmarshal\.loads?\s*\("), "severity": "high"},
    {"name": "assert used for security", "pattern": re.compile(r"\bassert\b.{0,60}(?:auth|permission|role|admin|login|token)", re.I), "severity": "medium"},
    {"name": "Hardcoded IP/host", "pattern": re.compile(r'(?:host|server|endpoint)\s*=\s*["\'](?:\d{1,3}\.){3}\d{1,3}["\']'), "severity": "low"},
]

_JS_TS_PATTERNS: list[dict] = [
    {"name": "eval() usage", "pattern": re.compile(r"\beval\s*\("), "severity": "high"},
    {"name": "innerHTML assignment", "pattern": re.compile(r"\.innerHTML\s*=\s*(?!['\"]\s*['\"])"), "severity": "high"},
    {"name": "dangerouslySetInnerHTML", "pattern": re.compile(r"dangerouslySetInnerHTML"), "severity": "high"},
    {"name": "document.write", "pattern": re.compile(r"\bdocument\.write\s*\("), "severity": "medium"},
    {"name": "Prototype pollution", "pattern": re.compile(r"__proto__|constructor\s*\[|Object\.assign\s*\(\s*\w+\s*,\s*\{"), "severity": "high"},
    {"name": "Insecure crypto random", "pattern": re.compile(r"Math\.random\(\).{0,50}(?:token|key|secret|nonce|salt)", re.I), "severity": "high"},
    {"name": "Child process with shell", "pattern": re.compile(r"(?:exec|spawn)\s*\([^)]*shell\s*:\s*true"), "severity": "critical"},
    {"name": "postMessage without origin check", "pattern": re.compile(r"addEventListener\s*\(\s*['\"]message['\"](?![\s\S]{0,200}origin)", re.I), "severity": "medium"},
    {"name": "Hardcoded secret in JS", "pattern": re.compile(r'(?:secret|apiKey|password|token)\s*[:=]\s*["\'][^"\']{12,}["\']', re.I), "severity": "high"},
]

_LANG_EXT: dict[str, str] = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "javascript",
    ".jsx": "javascript",
    ".tsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
}


def _safe_path(relative_path: str) -> Path:
    clean = relative_path.lstrip("/").lstrip("~")
    resolved = (_PROJECT_ROOT / clean).resolve()
    if not str(resolved).startswith(str(_PROJECT_ROOT)):
        raise ValueError(f"Path '{relative_path}' is outside the allowed project root")
    return resolved


def _iter_source_files(root: Path) -> list[Path]:
    files: list[Path] = []
    for f in root.rglob("*"):
        if not f.is_file():
            continue
        if any(part in _SKIP_DIRS or part.startswith(".") for part in f.parts):
            continue
        if f.stat().st_size > _MAX_FILE_SIZE:
            continue
        files.append(f)
    return files


def secrets_scan(path: str = ".") -> dict:
    try:
        target = _safe_path(path)
    except ValueError as exc:
        return {"error": str(exc), "blocked": True}

    hits: list[dict] = []
    files_scanned = 0

    for f in _iter_source_files(target):
        if f.suffix in {".pem", ".key", ".p12", ".pfx", ".jks", ".crt"}:
            continue
        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        files_scanned += 1

        for pattern_name, pattern in _SECRET_PATTERNS.items():
            for match in pattern.finditer(text):
                hit_text = match.group()
                if any(fp in hit_text.upper() for fp in _FALSE_POSITIVE_MARKERS):
                    continue
                line_num = text[: match.start()].count("\n") + 1
                preview = hit_text[:40] + "..." if len(hit_text) > 40 else hit_text
                hits.append({
                    "file": str(f.relative_to(_PROJECT_ROOT)),
                    "line": line_num,
                    "pattern": pattern_name,
                    "match_preview": preview,
                    "severity": "high",
                })

    severity_map = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    hits.sort(key=lambda x: severity_map.get(x["severity"], 99))

    return {
        "path": path,
        "files_scanned": files_scanned,
        "secrets_found": len(hits),
        "findings": hits[:50],
        "verdict": "FINDINGS" if hits else "CLEAN",
    }


def dependency_audit(path: str = ".") -> dict:
    try:
        _safe_path(path)
    except ValueError as exc:
        return {"error": str(exc), "blocked": True}

    results: dict[str, dict] = {}

    # Python requirements
    for candidate in [
        _PROJECT_ROOT / "requirements.txt",
        _PROJECT_ROOT / "backend" / "requirements.txt",
    ]:
        if candidate.exists():
            try:
                lines = candidate.read_text(encoding="utf-8").splitlines()
                packages = [l.strip() for l in lines if l.strip() and not l.startswith("#")]
                results["python"] = {
                    "file": str(candidate.relative_to(_PROJECT_ROOT)),
                    "packages": packages,
                    "count": len(packages),
                    "audit_command": f"pip-audit -r {candidate.relative_to(_PROJECT_ROOT)}",
                    "install_auditor": "pip install pip-audit",
                    "note": "Run pip-audit for CVE scanning",
                }
            except Exception:
                pass
            break

    # Node.js package.json
    for candidate in [
        _PROJECT_ROOT / "package.json",
        _PROJECT_ROOT / "frontend" / "package.json",
    ]:
        if candidate.exists():
            try:
                data = json.loads(candidate.read_text(encoding="utf-8"))
                deps = {**data.get("dependencies", {}), **data.get("devDependencies", {})}
                results["node"] = {
                    "file": str(candidate.relative_to(_PROJECT_ROOT)),
                    "packages": list(deps.keys()),
                    "count": len(deps),
                    "audit_command": f"cd {candidate.parent.relative_to(_PROJECT_ROOT)} && npm audit --json",
                    "note": "Run npm audit for CVE scanning",
                }
            except Exception:
                pass
            break

    lockfiles = [
        lf for lf in ["package-lock.json", "yarn.lock", "Pipfile.lock", "poetry.lock"]
        if (_PROJECT_ROOT / lf).exists()
        or (_PROJECT_ROOT / "frontend" / lf).exists()
    ]

    return {
        "path": path,
        "dependency_files": results,
        "lockfiles_present": lockfiles,
        "package_managers_found": list(results.keys()),
        "recommendation": "Run pip-audit (Python) and npm audit (Node) for CVE scanning",
    }


def code_security_patterns(path: str = ".", language: str = "auto") -> dict:
    try:
        target = _safe_path(path)
    except ValueError as exc:
        return {"error": str(exc), "blocked": True}

    findings: list[dict] = []
    files_scanned = 0

    for f in _iter_source_files(target):
        detected_lang = _LANG_EXT.get(f.suffix, "")
        if not detected_lang:
            continue
        if language != "auto" and detected_lang != language.lower():
            continue

        patterns = _PYTHON_PATTERNS if detected_lang == "python" else _JS_TS_PATTERNS

        try:
            text = f.read_text(encoding="utf-8", errors="ignore")
        except Exception:
            continue
        files_scanned += 1

        for check in patterns:
            for match in check["pattern"].finditer(text):
                line_num = text[: match.start()].count("\n") + 1
                line_content = text.splitlines()[line_num - 1].strip()[:150]
                findings.append({
                    "file": str(f.relative_to(_PROJECT_ROOT)),
                    "line": line_num,
                    "pattern": check["name"],
                    "severity": check["severity"],
                    "code_snippet": line_content,
                    "language": detected_lang,
                })

    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    findings.sort(key=lambda x: severity_order.get(x["severity"], 99))

    severity_counts: dict[str, int] = {}
    for f in findings:
        sev = f["severity"]
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    return {
        "path": path,
        "language_filter": language,
        "files_scanned": files_scanned,
        "findings_count": len(findings),
        "severity_breakdown": severity_counts,
        "findings": findings[:100],
        "verdict": "FINDINGS" if findings else "CLEAN",
    }
