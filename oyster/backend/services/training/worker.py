"""Child-process entry point for one LoRA training run.

WHY THIS EXISTS — the failure it prevents
=========================================
Training used to run in-process via ``asyncio.to_thread``. Loading an 8B model
inside a 3GB container is a cgroup OOM, and the kernel answers an OOM with
``SIGKILL``. A ``SIGKILL`` cannot be caught by ``except Exception`` — so the kill
landed on **uvicorn itself**: the API went down, the container restarted, and
the job row was left stranded at ``status="running"`` forever with nothing to
reap it.

Running the same code in a child process changes the outcome completely. If the
run is killed, the parent survives, reads the child's return code (``-9`` /
``137``), and records an honest failure. That is the difference between "OOM is
unlikely" (what a preflight estimate alone buys) and "OOM cannot take down the
API" (what the user actually asked for).

``lora_job.preflight`` is the first line of defence and refuses impossible runs
before a child is ever spawned. This module is the second: it assumes the
estimate might still be wrong, and makes being wrong survivable.

PROTOCOL
========
stdin  : one JSON object of run parameters.
stdout : exactly one line beginning with ``RESULT_PREFIX``, holding the JSON
         result. Anything else on stdout is progress noise from the ML stack and
         is ignored by the parent — hence the sentinel rather than "parse all of
         stdout", which HuggingFace's progress bars would otherwise corrupt.
"""

from __future__ import annotations

import json
import sys

RESULT_PREFIX = "__OYSTER_TRAINING_RESULT__:"


def _volunteer_for_the_oom_killer() -> None:
    """Ask the kernel to kill THIS process first if the cgroup runs out.

    The cgroup OOM killer scores candidates roughly by memory footprint, so the
    training child is already the likely victim — but "likely" is not a
    guarantee, and the whole point of this module is to remove the case where
    uvicorn is chosen instead. Writing the maximum ``oom_score_adj`` makes the
    child the definitive first choice.

    Deliberately NOT using ``RLIMIT_AS``: PyTorch reserves large virtual address
    ranges that far exceed its resident memory, so an address-space cap
    false-positives on runs that would have completed fine.
    """
    try:
        with open("/proc/self/oom_score_adj", "w", encoding="utf-8") as fh:
            fh.write("1000")
    except OSError:
        pass  # non-Linux dev box, or a sandbox that forbids it — not fatal


def main() -> int:
    try:
        payload = json.load(sys.stdin)
    except Exception as exc:  # noqa: BLE001
        sys.stdout.write(f"{RESULT_PREFIX}"
                         f'{{"ok": false, "status": "failed", "error": "bad worker payload: {exc}"}}')
        return 2

    _volunteer_for_the_oom_killer()

    # Imported here, not at module import time: this pulls in torch and is the
    # single most expensive import in the codebase. Keeping it inside main()
    # means a bad payload fails instantly instead of after a multi-second load.
    from services.training.lora_job import _train_sync

    try:
        result = _train_sync(
            payload["project_id"],
            payload["dataset_dir"],
            payload["base_model"],
            payload["epochs"],
            payload["learning_rate"],
            payload["adapter_dir"],
            max_seq_len=payload.get("max_seq_len", 1024),
        )
    except Exception as exc:  # noqa: BLE001 — report, never traceback to stderr only
        result = {"ok": False, "status": "failed", "error": f"{type(exc).__name__}: {exc}"}

    sys.stdout.write(RESULT_PREFIX + json.dumps(result))
    sys.stdout.flush()
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
