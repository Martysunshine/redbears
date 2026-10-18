"""Controlled tool runner.

The only place a tool actually runs. Guarantees:

- **No shell.** Subprocess tools are executed with an argv *array* and
  ``shell=False``; the binary is resolved to an absolute path; the constructed
  argv is re-checked for shell metacharacters before launch.
- **Minimal environment** and an explicit, project-scoped working directory.
- **Timeout** (process killed on expiry) and **cancellation** (kill/await-cancel
  via ``request_cancel``).
- **Output-size limits**, separate stdout/stderr capture, exit-code capture.
- **Secret redaction** applied to everything persisted (DB + logs), and an
  **output hash** over the stored (redacted) content for chain-of-custody.

Python adapters (HTTP/TLS/file) run in-process under the same timeout/cancel
contract but never touch a shell or the filesystem outside the artifact area.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
import shutil
from dataclasses import dataclass, field

import config
from services.media.redact import redact, scan as scan_secrets

from . import store
from .adapters.base import AdapterContext, AdapterResult
from .command_guard import CommandValidationError, check_argv
from .tool_registry import ToolAction, ToolProfile

# execution_id -> control handle (for cancellation)
_running: dict[str, dict] = {}


@dataclass
class RunOutcome:
    stdout: str = ""
    stderr: str = ""
    exit_code: int | None = 0
    tool_version: str | None = None
    parsed: dict = field(default_factory=dict)
    truncated: bool = False
    timeout_state: str = "none"       # none | timed_out
    cancellation_state: str = "none"  # none | cancelled
    error_summary: str | None = None
    output_hash: str = ""
    sanitized_command: str = ""
    secret_indicators: int = 0


def _output_dir(project_id: str, execution_id: str) -> str:
    d = config.DATA_DIR / "executions" / project_id / execution_id
    d.mkdir(parents=True, exist_ok=True)
    return str(d)


def _minimal_env() -> dict:
    return {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin:/usr/local/bin:/opt/homebrew/bin"),
        "HOME": os.environ.get("HOME", "/tmp"),
        "LANG": "C.UTF-8",
    }


def _finalize(text: str, max_bytes: int) -> tuple[str, bool, int]:
    """Redact + cap. Returns (redacted_capped_text, truncated, secret_count)."""
    indicators = len(scan_secrets(text)) if text else 0
    safe = redact(text) if text else ""
    truncated = False
    if len(safe.encode("utf-8", errors="ignore")) > max_bytes:
        safe = safe.encode("utf-8", errors="ignore")[:max_bytes].decode("utf-8", errors="ignore")
        truncated = True
    return safe, truncated, indicators


def request_cancel(execution_id: str) -> bool:
    """Request cancellation of a running execution. Returns True if it was running."""
    handle = _running.get(execution_id)
    if not handle:
        return False
    handle["cancel"] = True
    proc = handle.get("proc")
    task = handle.get("task")
    if proc and proc.returncode is None:
        try:
            proc.kill()
        except Exception:
            pass
    if task and not task.done():
        task.cancel()
    return True


async def run(execution_id: str, project_id: str, profile: ToolProfile, action: ToolAction,
              target: str, params: dict, scope: dict, timeout: int, max_output: int) -> RunOutcome:
    if action.kind == "subprocess":
        return await _run_subprocess(execution_id, project_id, profile, action, target, params, timeout, max_output)
    return await _run_python(execution_id, profile, action, target, params, scope, timeout, max_output)


# ---------------------------------------------------------------------------
# Python adapters
# ---------------------------------------------------------------------------

async def _run_python(execution_id, profile, action, target, params, scope, timeout, max_output) -> RunOutcome:
    ctx = AdapterContext(target=target, scope=scope, timeout_seconds=timeout,
                         max_output_bytes=max_output, parameters=params)
    handle: dict = {"cancel": False}
    _running[execution_id] = handle
    task = asyncio.ensure_future(action.runner(ctx))  # type: ignore[arg-type]
    handle["task"] = task
    try:
        result: AdapterResult = await asyncio.wait_for(task, timeout=timeout)
    except asyncio.TimeoutError:
        return _outcome_from_error("timed out", timeout_state="timed_out",
                                   version=_py_version(profile), sanitized=f"{profile.id}.{action.id}({target})")
    except asyncio.CancelledError:
        return _outcome_from_error("cancelled by operator", cancellation_state="cancelled",
                                   version=_py_version(profile), sanitized=f"{profile.id}.{action.id}({target})")
    except Exception as exc:  # noqa: BLE001
        return _outcome_from_error(f"adapter error: {exc}", version=_py_version(profile),
                                   sanitized=f"{profile.id}.{action.id}({target})")
    finally:
        _running.pop(execution_id, None)

    combined = result.stdout or ""
    safe_out, truncated, secrets = _finalize(combined, max_output)
    safe_err, _, _ = _finalize(result.stderr or "", 65536)
    return RunOutcome(
        stdout=safe_out,
        stderr=safe_err,
        exit_code=result.exit_code,
        tool_version=result.tool_version or _py_version(profile),
        parsed=_redact_parsed(result.parsed),
        truncated=truncated or result.truncated,
        error_summary=result.error_summary,
        output_hash=hashlib.sha256(safe_out.encode("utf-8", errors="ignore")).hexdigest(),
        sanitized_command=f"{profile.id}.{action.id}(target={target}, params={params})",
        secret_indicators=secrets,
    )


def _py_version(profile: ToolProfile) -> str | None:
    try:
        return profile.availability().get("version")
    except Exception:
        return None


# ---------------------------------------------------------------------------
# Subprocess adapters
# ---------------------------------------------------------------------------

async def _run_subprocess(execution_id, project_id, profile, action, target, params, timeout, max_output) -> RunOutcome:
    try:
        argv = action.build_argv(target, params)  # type: ignore[misc]
        check_argv(argv)
    except CommandValidationError as exc:
        return _outcome_from_error(f"command validation failed: {exc}")
    except Exception as exc:  # noqa: BLE001
        return _outcome_from_error(f"could not construct command: {exc}")

    binary = shutil.which(argv[0])
    if not binary:
        return _outcome_from_error(f"binary '{argv[0]}' not found on PATH (tool unavailable).")
    argv[0] = binary
    sanitized = " ".join(argv)

    outdir = _output_dir(project_id, execution_id)
    handle: dict = {"cancel": False}
    _running[execution_id] = handle
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            cwd=outdir,
            env=_minimal_env(),
        )
        handle["proc"] = proc
        try:
            raw_out, raw_err = await asyncio.wait_for(proc.communicate(), timeout=timeout)
            timeout_state = "none"
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            raw_out, raw_err = b"", b"process killed after timeout"
            timeout_state = "timed_out"
        exit_code = proc.returncode
        cancel_state = "cancelled" if handle.get("cancel") else "none"
    except Exception as exc:  # noqa: BLE001
        return _outcome_from_error(f"execution error: {exc}", sanitized=sanitized)
    finally:
        _running.pop(execution_id, None)

    out_text = raw_out.decode("utf-8", errors="replace") if isinstance(raw_out, bytes) else str(raw_out)
    err_text = raw_err.decode("utf-8", errors="replace") if isinstance(raw_err, bytes) else str(raw_err)
    safe_out, truncated, secrets = _finalize(out_text, max_output)
    safe_err, _, _ = _finalize(err_text, 65536)

    return RunOutcome(
        stdout=safe_out,
        stderr=safe_err,
        exit_code=exit_code,
        tool_version=profile.availability().get("version"),
        parsed={},  # parser runs in the service layer
        truncated=truncated,
        timeout_state=timeout_state,
        cancellation_state=cancel_state,
        error_summary=None if (exit_code == 0 and timeout_state == "none") else (safe_err[:200] or None),
        output_hash=hashlib.sha256(safe_out.encode("utf-8", errors="ignore")).hexdigest(),
        sanitized_command=sanitized,
        secret_indicators=secrets,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _redact_parsed(parsed: dict) -> dict:
    """Redact secret-looking strings inside parsed values (best effort)."""
    if not parsed:
        return {}
    try:
        import json
        return json.loads(redact(json.dumps(parsed)))
    except Exception:
        return parsed


def _outcome_from_error(message: str, *, timeout_state="none", cancellation_state="none",
                        version=None, sanitized="") -> RunOutcome:
    return RunOutcome(
        stdout="",
        stderr=message,
        exit_code=1 if timeout_state == "none" and cancellation_state == "none" else None,
        tool_version=version,
        timeout_state=timeout_state,
        cancellation_state=cancellation_state,
        error_summary=message,
        output_hash="",
        sanitized_command=sanitized,
    )
