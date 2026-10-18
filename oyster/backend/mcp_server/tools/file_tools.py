from __future__ import annotations

import fnmatch
from pathlib import Path

# Anchor to oyster/ project root
_PROJECT_ROOT = Path(__file__).parents[3].resolve()

MAX_FILE_SIZE = 1 * 1024 * 1024  # 1 MB
MAX_SEARCH_MATCHES = 100
MAX_SEARCH_FILES = 500

_SKIP_DIRS = {"__pycache__", "venv", "node_modules", ".next", ".git", "vector_db", ".cache"}
_BLOCKED_SUFFIXES = {".pem", ".key", ".p12", ".pfx", ".jks", ".crt", ".csr"}

_HOME = Path.home()
_ALWAYS_BLOCKED: list[Path] = [
    _HOME / ".ssh",
    _HOME / ".aws",
    _HOME / ".config",
    Path("/etc"),
    Path("/var"),
    Path("/private"),
    Path("/sys"),
    Path("/proc"),
]


def _safe_path(relative_path: str) -> Path:
    clean = relative_path.lstrip("/").lstrip("~")
    resolved = (_PROJECT_ROOT / clean).resolve()
    if not str(resolved).startswith(str(_PROJECT_ROOT)):
        raise ValueError(f"Path '{relative_path}' is outside the allowed project root")
    return resolved


def _is_sensitive(path: Path) -> bool:
    path_str = str(path)
    if path.suffix in _BLOCKED_SUFFIXES:
        return True
    # Block .env files (but allow reading with redaction — handled in read_file)
    for blocked in _ALWAYS_BLOCKED:
        if path_str.startswith(str(blocked)):
            return True
    # Block /Users paths outside project root
    if path_str.startswith("/Users/") and not path_str.startswith(str(_PROJECT_ROOT)):
        return True
    return False


def list_files(path: str = ".", pattern: str = "*") -> dict:
    try:
        target = _safe_path(path)
        if not target.exists():
            return {"error": f"Path '{path}' does not exist"}
        if target.is_file():
            return {"path": path, "entries": [{"name": target.name, "type": "file", "size": target.stat().st_size}], "total": 1}
        entries = []
        for item in sorted(target.iterdir()):
            if item.name.startswith(".") or item.name in _SKIP_DIRS:
                continue
            if not fnmatch.fnmatch(item.name, pattern):
                continue
            entries.append({
                "name": item.name,
                "type": "directory" if item.is_dir() else "file",
                "size": item.stat().st_size if item.is_file() else None,
            })
        return {"path": path, "entries": entries, "total": len(entries)}
    except ValueError as exc:
        return {"error": str(exc), "blocked": True}
    except Exception as exc:
        return {"error": f"list_files failed: {exc}"}


def read_file(path: str) -> dict:
    try:
        target = _safe_path(path)
        if _is_sensitive(target):
            return {"error": f"Access to '{path}' is blocked (sensitive path)", "blocked": True}
        if not target.exists():
            return {"error": f"File '{path}' does not exist"}
        if not target.is_file():
            return {"error": f"'{path}' is not a file"}
        size = target.stat().st_size
        if size > MAX_FILE_SIZE:
            return {"error": f"File too large ({size} bytes, max 1 MB)"}
        content = target.read_text(encoding="utf-8", errors="replace")
        # Redact .env values — show keys only
        if target.name.startswith(".env") or target.suffix == ".env":
            redacted = []
            for line in content.splitlines():
                if "=" in line and not line.lstrip().startswith("#"):
                    redacted.append(line.split("=")[0] + "=<REDACTED>")
                else:
                    redacted.append(line)
            content = "\n".join(redacted) + "\n[.env values redacted]"
        return {"path": path, "content": content, "size": size, "lines": content.count("\n") + 1}
    except ValueError as exc:
        return {"error": str(exc), "blocked": True}
    except Exception as exc:
        return {"error": f"read_file failed: {exc}"}


def write_file(path: str, content: str) -> dict:
    """Write (or overwrite) a file within the project root.

    Migrated from the legacy registry. Unlike that version this refuses to write
    to sensitive paths (.env, keys, ~/.ssh, /etc, …) via ``_is_sensitive``.
    """
    try:
        target = _safe_path(path)
        if _is_sensitive(target):
            return {"error": f"Writing to '{path}' is blocked (sensitive path)", "blocked": True}
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding="utf-8")
        return {"path": path, "written": True, "size": len(content.encode("utf-8"))}
    except ValueError as exc:
        return {"error": str(exc), "blocked": True}
    except Exception as exc:
        return {"error": f"write_file failed: {exc}"}


def search_files(query: str, path: str = ".", file_pattern: str = "*") -> dict:
    try:
        target = _safe_path(path)
        matches: list[dict] = []
        file_count = 0
        for f in target.rglob(file_pattern):
            if file_count >= MAX_SEARCH_FILES or len(matches) >= MAX_SEARCH_MATCHES:
                break
            if not f.is_file():
                continue
            if any(part in _SKIP_DIRS or part.startswith(".") for part in f.parts):
                continue
            if _is_sensitive(f):
                continue
            if f.stat().st_size > MAX_FILE_SIZE:
                continue
            file_count += 1
            try:
                text = f.read_text(encoding="utf-8", errors="ignore")
                for i, line in enumerate(text.splitlines(), 1):
                    if query.lower() in line.lower():
                        matches.append({
                            "file": str(f.relative_to(_PROJECT_ROOT)),
                            "line": i,
                            "content": line.strip()[:200],
                        })
                        if len(matches) >= MAX_SEARCH_MATCHES:
                            break
            except Exception:
                continue
        return {"query": query, "matches": matches, "total": len(matches), "files_searched": file_count}
    except ValueError as exc:
        return {"error": str(exc), "blocked": True}
    except Exception as exc:
        return {"error": f"search_files failed: {exc}"}


def inspect_project(path: str = ".") -> dict:
    try:
        target = _safe_path(path)

        def _tree(p: Path, depth: int) -> dict:
            node: dict = {"name": p.name, "type": "directory" if p.is_dir() else "file"}
            if p.is_dir() and depth < 3:
                children = []
                for child in sorted(p.iterdir()):
                    if child.name in _SKIP_DIRS or child.name.startswith("."):
                        continue
                    children.append(_tree(child, depth + 1))
                node["children"] = children
            elif p.is_file():
                node["size"] = p.stat().st_size
            return node

        return {"path": path, "tree": _tree(target, 0)}
    except ValueError as exc:
        return {"error": str(exc), "blocked": True}
    except Exception as exc:
        return {"error": f"inspect_project failed: {exc}"}
