"""Parameter/command validation — defence in depth.

Even though every external tool is executed with an argv *array* and
``shell=False`` (so the shell never interprets metacharacters), we still reject
dangerous parameter values before they are placed into argv. This catches
attempts to smuggle shell chaining, command substitution, redirection, env-var
injection, path traversal and unsafe wildcards through a "target" or "flag"
field, and gives a precise reason for the block.
"""

from __future__ import annotations

import re

# Characters/sequences that must never appear in a tool parameter value.
_SHELL_METACHARS = set(";|&`$><\n\r\\")
_SUBSTITUTION = ("$(", "${", "`", "<(", ">(")
_TRAVERSAL = ("..", "%2e%2e", "%2f", "%5c")


class CommandValidationError(ValueError):
    """Raised when a parameter value is rejected by the guard."""


def check_value(name: str, value: str) -> None:
    """Raise CommandValidationError if ``value`` is unsafe for argv use."""
    if value is None:
        return
    s = str(value)

    bad = _SHELL_METACHARS.intersection(s)
    if bad:
        raise CommandValidationError(
            f"Parameter '{name}' contains shell metacharacter(s) {sorted(bad)} — rejected."
        )
    for token in _SUBSTITUTION:
        if token in s:
            raise CommandValidationError(
                f"Parameter '{name}' contains command-substitution '{token}' — rejected."
            )
    for token in _TRAVERSAL:
        if token in s.lower():
            raise CommandValidationError(
                f"Parameter '{name}' contains path traversal '{token}' — rejected."
            )
    if re.search(r"\b[A-Z_][A-Z0-9_]*=", s) and "://" not in s:
        # e.g. "LD_PRELOAD=/x" env injection
        raise CommandValidationError(
            f"Parameter '{name}' looks like an environment-variable assignment — rejected."
        )
    if s.count("*") > 1 or (s.startswith("*") and len(s) > 1):
        raise CommandValidationError(
            f"Parameter '{name}' contains an unsafe wildcard expansion — rejected."
        )


def check_argv(argv: list[str]) -> None:
    """Final gate before execution: no argument may contain a shell metachar."""
    for i, arg in enumerate(argv):
        for ch in _SHELL_METACHARS:
            if ch in arg and not (i == 0):  # arg[0] is the resolved binary path
                # allow backslash only inside the binary path (Windows); reject elsewhere
                raise CommandValidationError(
                    f"Constructed argv entry '{arg}' contains a shell metacharacter — refused."
                )


def sanitize_flag(flag: str) -> str:
    """Normalise a flag token; raise if it is not a plain option."""
    check_value("flag", flag)
    return flag
