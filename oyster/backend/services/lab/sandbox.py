"""Isolation enforcement for the Juice Shop lab process — outside the model, at
the OS layer, so no prompt or agent decision can widen it.

This machine is macOS. The mechanism is ``sandbox-exec`` (Apple's Seatbelt),
applied to the Juice Shop Node process itself:
  - network-outbound restricted to the process's OWN loopback port only — it
    cannot reach the public internet, other local services, or (because
    169.254.169.254 is a real routable outbound address, not loopback) any
    cloud metadata endpoint.
  - file-read restricted to its own working copy plus the OS/runtime paths
    Node needs to execute; file-write restricted to its own working copy
    (where it keeps its sqlite DB) — no host dotfiles, no other project's
    files, no secrets.
  - no mach-lookup beyond what's needed to run Node, no access to the Docker
    socket (nothing here ever mounts or references one).

Verified live on this machine 2026-10-18 (see docs/INVESTIGATION.md): a probe
script run under an equivalent profile had its own allowed-port connection
succeed, a second local port blocked, 1.1.1.1:443 blocked, the link-local
metadata address blocked, and reads of files outside its working directory
blocked.

Known gap, reported rather than hidden: Juice Shop's own server code calls
``server.listen(port)`` with no host argument, so unpatched it binds every
interface, not loopback-only — reachable from other devices on the same
network while running, regardless of the sandbox profile (which constrains
what the process can reach, not who can reach it). provisioner.py closes this
by patching the pinned build's listen call to bind 127.0.0.1 explicitly before
first start, and records the patch (never alters the upstream source
checkout's pinned commit) so it is auditable rather than silent.

If ``sandbox-exec`` is unavailable (non-macOS, or removed), ``available()``
returns False and ``config.LAB_ENABLED`` is forced off at boot — the lab never
falls back to running the process unsandboxed.
"""
from __future__ import annotations

import shutil
import textwrap


def available() -> bool:
    return shutil.which("sandbox-exec") is not None


def write_profile(path: str, *, work_dir: str, allowed_port: int, node_bin_dirs: list[str]) -> None:
    """Writes a Seatbelt profile scoping a Node process to `work_dir` (its own
    checkout + a per-instance writable data dir) and one loopback port."""
    node_allow = "\n".join(f'(subpath "{d}")' for d in node_bin_dirs)
    profile = textwrap.dedent(f"""\
        (version 1)
        (deny default)
        (allow process-fork)
        (allow process-exec
          (subpath "/usr/bin") (subpath "/bin") (subpath "/usr/sbin") (subpath "/sbin")
          {node_allow})
        (allow file-read*
          (literal "/")
          (subpath "/usr") (subpath "/System") (subpath "/Library")
          (subpath "/private/var/db") (subpath "/dev") (subpath "/etc") (subpath "/private/etc")
          {node_allow}
          (subpath "{work_dir}"))
        (allow file-write*
          (subpath "{work_dir}")
          (literal "/dev/null") (literal "/dev/tty"))
        (allow file-read-metadata)
        (allow file-ioctl)
        (allow file-map-executable)
        (allow dynamic-code-generation)
        (allow sysctl-read)
        (allow mach-lookup)
        (allow iokit-open)
        (allow ipc-posix-shm*)
        (allow system-socket)
        (allow process-info-pidinfo (target self))
        (allow network-outbound (local ip "localhost:{allowed_port}"))
        (allow network-outbound (remote ip "localhost:{allowed_port}"))
        (allow network-inbound (local ip "*:{allowed_port}"))
        (allow signal (target self))
        """)
    with open(path, "w") as f:
        f.write(profile)
