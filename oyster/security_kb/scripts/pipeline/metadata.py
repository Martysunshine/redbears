"""Derive and validate metadata for each document chunk."""

from __future__ import annotations

import re
from pathlib import Path


# ── severity / attack type keyword maps ──────────────────────────────────────

_ATTACK_KEYWORDS: dict[str, list[str]] = {
    "sqli":      ["sql injection", "sqli", "union select", "blind sql"],
    "xss":       ["cross-site scripting", "xss", "stored xss", "reflected xss"],
    "ssrf":      ["ssrf", "server-side request forgery"],
    "xxe":       ["xxe", "xml external entity"],
    "idor":      ["idor", "insecure direct object"],
    "rce":       ["remote code execution", "rce", "command injection", "os command"],
    "auth":      ["authentication bypass", "broken auth", "session fixation", "jwt", "oauth"],
    "api":       ["api security", "rest api", "graphql", "api key", "rate limit"],
    "crypto":    ["weak cipher", "tls", "ssl", "certificate", "hash collision"],
    "lfi":       ["local file inclusion", "lfi", "path traversal", "directory traversal"],
    "rfi":       ["remote file inclusion", "rfi"],
    "csrf":      ["csrf", "cross-site request forgery"],
    "deserialization": ["deserialization", "pickle", "java deserialize"],
    "misconfig": ["misconfiguration", "default credentials", "exposed admin"],
    "llm":       ["prompt injection", "jailbreak", "llm", "rag poisoning", "ai security"],
}

_SEVERITY_KEYWORDS: dict[str, list[str]] = {
    "critical": ["critical", "cvss 9", "cvss 10", "rce", "remote code execution"],
    "high":     ["high severity", "cvss 7", "cvss 8", "sql injection", "authentication bypass"],
    "medium":   ["medium severity", "cvss 4", "cvss 5", "cvss 6", "xss", "idor"],
    "low":      ["low severity", "cvss 1", "cvss 2", "cvss 3", "information disclosure"],
}

_DIFFICULTY_KEYWORDS: dict[str, list[str]] = {
    "advanced":       ["exploit chain", "zero-day", "kernel", "heap spray", "rop chain"],
    "intermediate":   ["blind", "second-order", "filter bypass", "waf bypass"],
    "beginner":       ["basic", "simple", "default password", "missing header"],
}


def _match_keywords(text_lower: str, kw_map: dict[str, list[str]]) -> list[str]:
    return [
        label
        for label, keywords in kw_map.items()
        if any(kw in text_lower for kw in keywords)
    ]


def _detect_language(path: Path) -> str:
    ext = path.suffix.lower()
    return {
        ".py": "python", ".js": "javascript", ".ts": "typescript",
        ".go": "go", ".java": "java", ".rb": "ruby", ".php": "php",
        ".rs": "rust", ".c": "c", ".cpp": "cpp", ".sh": "shell",
        ".yaml": "yaml", ".yml": "yaml", ".json": "json",
        ".md": "markdown", ".txt": "text", ".html": "html",
    }.get(ext, "unknown")


def build_metadata(
    *,
    source_path: Path,
    category: str,
    source_repo: str = "",
    chunk_index: int = 0,
    chunk_count: int = 1,
    text: str = "",
    extra: dict | None = None,
) -> dict:
    text_lower = text.lower()
    attack_types = _match_keywords(text_lower, _ATTACK_KEYWORDS)
    severities = _match_keywords(text_lower, _SEVERITY_KEYWORDS)
    difficulties = _match_keywords(text_lower, _DIFFICULTY_KEYWORDS)

    tags: list[str] = list({*attack_types, *severities, *difficulties, category})

    return {
        "source": str(source_path),
        "category": category,
        "tool": source_repo,
        "attack_type": ", ".join(attack_types) if attack_types else "general",
        "difficulty": difficulties[0] if difficulties else "intermediate",
        "language": _detect_language(source_path),
        "tags": ", ".join(sorted(tags)),
        "chunk_index": chunk_index,
        "chunk_count": chunk_count,
        **(extra or {}),
    }
