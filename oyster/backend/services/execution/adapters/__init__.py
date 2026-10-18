"""Typed tool adapters for the Execution Engine.

Every adapter turns validated, allow-listed parameters into a real observation
without ever handing a free-form string to a shell. Two kinds exist:

- **python adapters** — pure-Python inspectors (HTTP, TLS, file analysis) that
  are always available and never spawn a shell.
- **subprocess adapters** — build an argv *array* (never a string) for an
  allow-listed external binary (nmap, semgrep…) and let the controlled runner
  execute it with ``shell=False``.
"""

from __future__ import annotations
