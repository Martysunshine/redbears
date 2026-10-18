"""Oyster Execution Engine — authorization-aware cybersecurity tool execution.

This package turns "run a tool against a target" into a deterministic pipeline
that lives *outside* the LLM:

    request → intent/target → project → scope validation → tool lookup →
    risk classification → policy decision → approval → command construction →
    command validation → controlled execution → output capture → evidence →
    audit → structured response

The model may *propose* an action, but it can never invoke an unrestricted
shell. Every real execution is gated by scope + policy + (for intrusive
classes) explicit human approval, and every step is recorded.

Modules
-------
- ``store``         SQLite schema + persistence (idempotent migrations)
- ``scope_engine``  normalized target validation against project scope
- ``risk``          deterministic execution classes (0–4)
- ``tool_registry`` typed tool profiles + adapters (http, tls, file, nmap…)
- ``policy``        PolicyDecision (scope + risk + approval + constraints)
- ``runner``        controlled runner (no shell, arg arrays, timeout, redact)
- ``parsers``       raw tool output → structured observations
- ``service``       orchestration of the proposal → execution lifecycle
"""

from __future__ import annotations
