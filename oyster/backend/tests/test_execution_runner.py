"""Controlled runner — file analysis, hashing, secret redaction, timeout."""

from __future__ import annotations

import asyncio

import pytest

import config
from services.execution import runner, tool_registry


def _write_artifact(name: str, content: str):
    config.ARTIFACTS_DIR.mkdir(parents=True, exist_ok=True)
    p = config.ARTIFACTS_DIR / name
    p.write_text(content, encoding="utf-8")
    return p


@pytest.mark.asyncio
async def test_file_analysis_hash_and_redaction():
    _write_artifact("leak.txt", "config\nAKIAIOSFODNN7EXAMPLE\npassword=SuperSecret123\n")
    prof, act = tool_registry.get_action("file", "analyze")
    outcome = await runner.run("exec_t1", "proj_t", prof, act, "leak.txt", {}, {}, 30, 1_000_000)
    assert outcome.exit_code == 0
    assert len(outcome.output_hash) == 64                      # sha256 present
    assert outcome.secret_indicators >= 1                      # secret detected
    assert "SuperSecret123" not in outcome.stdout               # redacted from output
    assert outcome.parsed.get("sha256")


@pytest.mark.asyncio
async def test_file_analysis_path_traversal_refused():
    prof, act = tool_registry.get_action("file", "analyze")
    outcome = await runner.run("exec_t2", "proj_t", prof, act, "../../etc/passwd", {}, {}, 30, 1_000_000)
    assert outcome.exit_code == 2 and "not a readable file" in (outcome.error_summary or "")


@pytest.mark.asyncio
async def test_python_adapter_timeout():
    # a python action whose runner sleeps beyond the timeout → timed_out state
    prof, act = tool_registry.get_action("file", "analyze")

    async def _slow(ctx):
        await asyncio.sleep(5)
    object.__setattr__(act, "runner", _slow)
    try:
        outcome = await runner.run("exec_t3", "proj_t", prof, act, "leak.txt", {}, {}, 1, 1000)
        assert outcome.timeout_state == "timed_out"
    finally:
        # restore the real adapter for other tests
        from services.execution.adapters import file_analysis
        object.__setattr__(act, "runner", file_analysis.run)
