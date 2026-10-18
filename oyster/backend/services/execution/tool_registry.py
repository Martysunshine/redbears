"""Typed tool registry — the ONLY interface for real execution.

A free-form, model-generated shell command is never the execution interface.
Instead every capability is a typed :class:`ToolAction` on a :class:`ToolProfile`
with an explicit parameter schema, allow-listed flags, an execution class, and
either a pure-Python adapter or an argv-builder for an allow-listed binary.

Availability is checked at runtime (``shutil.which``); a missing binary is
reported as *unavailable* with install guidance — output is never fabricated.
"""

from __future__ import annotations

import shutil
import subprocess
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

from . import risk
from .adapters import file_analysis, http_inspect, tls_inspect
from .adapters.base import AdapterContext, AdapterResult
from .command_guard import CommandValidationError, check_value

PyRunner = Callable[[AdapterContext], Awaitable[AdapterResult]]
ArgvBuilder = Callable[[str, dict], list[str]]


@dataclass
class ToolAction:
    id: str
    name: str
    description: str
    execution_class: int
    target_types: list[str]
    network_required: bool
    param_schema: dict = field(default_factory=dict)
    kind: str = "python"                 # "python" | "subprocess"
    runner: PyRunner | None = None        # python adapters
    build_argv: ArgvBuilder | None = None  # subprocess adapters
    cleanup_required: bool = False


@dataclass
class ToolProfile:
    id: str
    name: str
    description: str
    official_docs: str
    binary: str | None                    # None => pure python (always available)
    supported_os: list[str]
    actions: list[ToolAction]
    prohibited_flags: list[str] = field(default_factory=list)
    install_hint: str = ""

    # -- availability -----------------------------------------------------
    def availability(self) -> dict:
        if self.binary is None:
            return {"available": True, "version": self._py_version(), "reason": "built-in (pure Python)"}
        path = shutil.which(self.binary)
        if not path:
            return {
                "available": False,
                "version": None,
                "reason": f"'{self.binary}' not found on PATH.",
                "install_hint": self.install_hint,
            }
        return {"available": True, "version": self._binary_version(path), "path": path,
                "reason": "installed"}

    def _py_version(self) -> str:
        try:
            mod = {"http_inspect": http_inspect, "tls_inspect": tls_inspect,
                   "file_analysis": file_analysis}
            # pick the first action's adapter module version if available
            if self.id == "http":
                return http_inspect.version()
            if self.id == "tls":
                return tls_inspect.version()
            if self.id == "file":
                return file_analysis.version()
        except Exception:
            pass
        return "1.0"

    def _binary_version(self, path: str) -> str | None:
        try:
            out = subprocess.run([path, "--version"], capture_output=True, text=True, timeout=5)
            return (out.stdout or out.stderr).splitlines()[0].strip()[:120]
        except Exception:
            return None

    def get_action(self, action_id: str) -> ToolAction | None:
        return next((a for a in self.actions if a.id == action_id), None)


# ---------------------------------------------------------------------------
# Parameter validation
# ---------------------------------------------------------------------------

def validate_parameters(action: ToolAction, params: dict) -> dict:
    """Validate + coerce params against the action schema. Returns the cleaned
    dict or raises CommandValidationError."""
    clean: dict = {}
    schema = action.param_schema or {}
    for name, spec in schema.items():
        if name in params and params[name] is not None:
            value = params[name]
        elif "default" in spec:
            value = spec["default"]
        elif spec.get("required"):
            raise CommandValidationError(f"Missing required parameter '{name}'.")
        else:
            continue

        ptype = spec.get("type", "string")
        if ptype == "int":
            try:
                value = int(value)
            except (TypeError, ValueError):
                raise CommandValidationError(f"Parameter '{name}' must be an integer.")
            lo, hi = spec.get("min"), spec.get("max")
            if lo is not None:
                value = max(lo, value)
            if hi is not None:
                value = min(hi, value)
        else:
            value = str(value)
            check_value(name, value)  # reject shell metachars / traversal / env-injection
            enum = spec.get("enum")
            if enum and value not in enum:
                raise CommandValidationError(
                    f"Parameter '{name}'='{value}' not in allowed values {enum}."
                )
        clean[name] = value
    return clean


# ---------------------------------------------------------------------------
# Subprocess argv builders (allow-listed flags only)
# ---------------------------------------------------------------------------

def _nmap_version(_target: str, _params: dict) -> list[str]:
    return ["nmap", "--version"]


def _nmap_host_discovery(target: str, _params: dict) -> list[str]:
    check_value("target", target)
    return ["nmap", "-sn", "-n", "-T3", target]


def _nmap_port_scan(target: str, params: dict) -> list[str]:
    check_value("target", target)
    top = int(params.get("top_ports", 100))
    return ["nmap", "-Pn", "-T3", "--top-ports", str(top), target]


def _nmap_service_detection(target: str, params: dict) -> list[str]:
    check_value("target", target)
    top = int(params.get("top_ports", 50))
    return ["nmap", "-Pn", "-sV", "-T3", "--top-ports", str(top), target]


def _semgrep_scan(target: str, params: dict) -> list[str]:
    check_value("path", target)
    ruleset = params.get("ruleset", "auto")
    check_value("ruleset", ruleset)
    return ["semgrep", "--config", ruleset, "--json", "--timeout", "60", "--quiet", target]


# ---------------------------------------------------------------------------
# The registry
# ---------------------------------------------------------------------------

_PROFILES: dict[str, ToolProfile] = {}


def _register(profile: ToolProfile) -> None:
    _PROFILES[profile.id] = profile


_register(ToolProfile(
    id="http",
    name="HTTP Inspector",
    description="Inspect an in-scope HTTP(S) endpoint: status, headers, redirect chain, TLS metadata, security headers. Manually re-validates every redirect against scope.",
    official_docs="https://developer.mozilla.org/en-US/docs/Web/HTTP",
    binary=None,
    supported_os=["darwin", "linux", "windows"],
    prohibited_flags=[],
    actions=[
        ToolAction(
            id="inspect",
            name="Inspect endpoint",
            description="Single HEAD/GET/OPTIONS request with header, redirect and TLS capture.",
            execution_class=risk.CLASS_LOW_ACTIVE,
            target_types=["url", "host"],
            network_required=True,
            kind="python",
            runner=http_inspect.run,
            param_schema={
                "method": {"type": "string", "enum": ["GET", "HEAD", "OPTIONS"], "default": "GET",
                           "description": "HTTP method (safe methods only)."},
                "max_body_bytes": {"type": "int", "min": 0, "max": 1_048_576, "default": 65536,
                                   "description": "Max response body bytes to capture."},
            },
        ),
    ],
))

_register(ToolProfile(
    id="tls",
    name="TLS Inspector",
    description="Inspect a host's TLS certificate and negotiated protocol/cipher via one handshake.",
    official_docs="https://docs.python.org/3/library/ssl.html",
    binary=None,
    supported_os=["darwin", "linux", "windows"],
    actions=[
        ToolAction(
            id="inspect",
            name="Inspect TLS",
            description="One TLS handshake; reports cert subject/issuer/validity, protocol, cipher.",
            execution_class=risk.CLASS_LOW_ACTIVE,
            target_types=["host", "url", "ip"],
            network_required=True,
            kind="python",
            runner=tls_inspect.run,
            param_schema={
                "port": {"type": "int", "min": 1, "max": 65535, "default": 443,
                         "description": "TLS port."},
            },
        ),
    ],
))

_register(ToolProfile(
    id="file",
    name="Local File Analysis",
    description="Read-only analysis of a file already stored in the project's artifact area: hashes, size, secret indicators, safe archive listing. Never executes uploaded code.",
    official_docs="https://docs.python.org/3/library/hashlib.html",
    binary=None,
    supported_os=["darwin", "linux", "windows"],
    actions=[
        ToolAction(
            id="analyze",
            name="Analyze file",
            description="Hash + metadata + secret-indicator scan of a stored artifact.",
            execution_class=risk.CLASS_READ_ONLY,
            target_types=["file"],
            network_required=False,
            kind="python",
            runner=file_analysis.run,
            param_schema={
                "path": {"type": "string", "required": False,
                         "description": "Artifact-relative path (falls back to target)."},
            },
        ),
    ],
))

_register(ToolProfile(
    id="nmap",
    name="Nmap",
    description="Network mapper. Host discovery, port and service detection. No unsafe NSE categories by default.",
    official_docs="https://nmap.org/book/man.html",
    binary="nmap",
    supported_os=["darwin", "linux", "windows"],
    install_hint="brew install nmap  (macOS) · apt install nmap (Debian/Ubuntu)",
    prohibited_flags=["--script", "-sS", "-O", "--script-args", "-oA", "-iL"],
    actions=[
        ToolAction(
            id="version", name="Version check",
            description="nmap --version (local, no target).",
            execution_class=risk.CLASS_READ_ONLY, target_types=["none"],
            network_required=False, kind="subprocess", build_argv=_nmap_version,
        ),
        ToolAction(
            id="host_discovery", name="Host discovery",
            description="nmap -sn -n -T3 <target> — ping/ARP discovery, no port scan.",
            execution_class=risk.CLASS_LOW_ACTIVE, target_types=["host", "ip"],
            network_required=True, kind="subprocess", build_argv=_nmap_host_discovery,
        ),
        ToolAction(
            id="port_scan", name="Top-ports scan",
            description="nmap -Pn -T3 --top-ports N <target>.",
            execution_class=risk.CLASS_LOW_ACTIVE, target_types=["host", "ip"],
            network_required=True, kind="subprocess", build_argv=_nmap_port_scan,
            param_schema={"top_ports": {"type": "int", "min": 1, "max": 1000, "default": 100,
                                        "description": "Number of top ports."}},
        ),
        ToolAction(
            id="service_detection", name="Service detection",
            description="nmap -Pn -sV -T3 --top-ports N <target>.",
            execution_class=risk.CLASS_LOW_ACTIVE, target_types=["host", "ip"],
            network_required=True, kind="subprocess", build_argv=_nmap_service_detection,
            param_schema={"top_ports": {"type": "int", "min": 1, "max": 500, "default": 50,
                                        "description": "Number of top ports."}},
        ),
    ],
))

_register(ToolProfile(
    id="semgrep",
    name="Semgrep",
    description="Static application security testing over a repository/path. Read-only local analysis.",
    official_docs="https://semgrep.dev/docs/",
    binary="semgrep",
    supported_os=["darwin", "linux"],
    install_hint="pip install semgrep  ·  brew install semgrep",
    actions=[
        ToolAction(
            id="scan", name="Static scan",
            description="semgrep --config <ruleset> --json <path>.",
            execution_class=risk.CLASS_READ_ONLY, target_types=["file", "path"],
            network_required=False, kind="subprocess", build_argv=_semgrep_scan,
            param_schema={"ruleset": {"type": "string",
                                      "enum": ["auto", "p/default", "p/security-audit", "p/owasp-top-ten"],
                                      "default": "auto",
                                      "description": "Semgrep ruleset."}},
        ),
    ],
))


# ---------------------------------------------------------------------------
# Public accessors
# ---------------------------------------------------------------------------

def all_profiles() -> list[ToolProfile]:
    return list(_PROFILES.values())


def get_profile(tool_id: str) -> ToolProfile | None:
    return _PROFILES.get(tool_id)


def get_action(tool_id: str, action_id: str) -> tuple[ToolProfile, ToolAction] | None:
    prof = _PROFILES.get(tool_id)
    if not prof:
        return None
    act = prof.get_action(action_id)
    if not act:
        return None
    return prof, act


def describe() -> list[dict]:
    """Serialisable catalogue for the API / frontend."""
    out = []
    for p in _PROFILES.values():
        avail = p.availability()
        out.append({
            "id": p.id,
            "name": p.name,
            "description": p.description,
            "official_docs": p.official_docs,
            "binary": p.binary,
            "supported_os": p.supported_os,
            "install_hint": p.install_hint,
            "prohibited_flags": p.prohibited_flags,
            "availability": avail,
            "actions": [
                {
                    "id": a.id,
                    "name": a.name,
                    "description": a.description,
                    "execution_class": a.execution_class,
                    "execution_class_name": risk.CLASS_NAMES[a.execution_class],
                    "risk_level": risk.RISK_LABEL[a.execution_class],
                    "target_types": a.target_types,
                    "network_required": a.network_required,
                    "param_schema": a.param_schema,
                    "approval": risk.profile_for_class(a.execution_class).default_approval,
                }
                for a in p.actions
            ],
        })
    return out
