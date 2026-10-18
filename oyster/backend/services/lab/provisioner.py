"""Disposable Juice Shop lab instance lifecycle: create, reset, cleanup, TTL
sweep. See sandbox.py for the OS-level isolation this wraps every instance in,
and telemetry_proxy.py for the collector sitting between the test runner and
the target.

Every instance is its OWN filesystem copy of the pinned checkout (an APFS
clone — ``cp -c``, so it costs no extra disk until written to), so one
instance's synthetic data/state can never leak into another's and reset/
cleanup only ever touches that one copy.

Provenance: before starting anything, ``_verify_pinned_commit`` checks the
pristine checkout's HEAD against ``config.LAB_JUICE_SHOP_COMMIT``. A moved tag
or a dirty source checkout refuses to provision rather than silently running
different code than what is documented.

Known, documented patch (see sandbox.py's docstring for why): Juice Shop's
built server listens on every interface by default. ``_ensure_loopback_patch``
rewrites exactly one line of the instance's OWN ``build/server.js`` — never
the pristine checkout — to bind 127.0.0.1, and records the before/after hash
in the instance record so the change is auditable, not silent.
"""
from __future__ import annotations

import dataclasses
import hashlib
import shutil
import signal
import subprocess
import threading
import time
import uuid
from pathlib import Path

import httpx

import config
import log_config
from services.lab import sandbox, selftest
from services.lab.telemetry_proxy import TelemetryProxy

_INSTANCES_DIR = Path.home() / "redbears-assets" / "lab" / "instances"
_TELEMETRY_DIR = Path.home() / "redbears-assets" / "lab" / "telemetry"
_NODE_BIN_DIRS = ["/usr/local/bin", "/opt/homebrew/bin", "/usr/local/lib/node_modules"]

_LISTEN_ORIGINAL = "server.listen(port, () => {"
_LISTEN_PATCHED = "server.listen(port, '127.0.0.1', () => {"


class LabDisabled(Exception):
    pass


class LabCapacityReached(Exception):
    pass


class LabProvisionError(Exception):
    pass


@dataclasses.dataclass
class LabInstance:
    id: str
    app_port: int
    proxy_port: int
    instance_dir: Path
    telemetry_path: Path
    created_at: float
    scenario_id: str | None
    status: str = "starting"  # starting | ready | error | stopped
    error: str | None = None
    patch_applied: bool = False
    patch_before_sha256: str | None = None
    patch_after_sha256: str | None = None
    process: subprocess.Popen | None = dataclasses.field(default=None, repr=False)
    telemetry: TelemetryProxy | None = dataclasses.field(default=None, repr=False)

    @property
    def base_url(self) -> str:
        """The ONLY URL the test runner (services/scenarios/runner.py) is ever
        given — the telemetry collector's port, never the target directly."""
        return f"http://127.0.0.1:{self.proxy_port}"

    def public_dict(self) -> dict:
        return {
            "id": self.id, "status": self.status, "error": self.error,
            "base_url": self.base_url if self.status == "ready" else None,
            "scenario_id": self.scenario_id, "created_at": self.created_at,
            "patch_applied": self.patch_applied,
            "ttl_s": config.LAB_INSTANCE_TTL_S,
            "expires_at": self.created_at + config.LAB_INSTANCE_TTL_S,
        }


_instances: dict[str, LabInstance] = {}
_ports_in_use: set[int] = set()
_lock = threading.Lock()


def _lab_enabled() -> tuple[bool, str]:
    if not config.LAB_ENABLED:
        return False, "Lab is disabled by configuration (LAB_ENABLED=false)."
    if not sandbox.available():
        return False, ("sandbox-exec is not available on this host, so the isolation boundary "
                       "in services/lab/sandbox.py cannot be enforced. Refusing to run the lab "
                       "unsandboxed rather than substituting unrestricted host execution.")
    src = Path(config.LAB_JUICE_SHOP_DIR)
    if not src.is_dir():
        return False, f"No Juice Shop checkout at {src} (see scripts/setup-lab.sh)."
    # Fail closed: the sandbox must demonstrably confine a probe process before
    # any lab instance is allowed to run (services/lab/selftest.py).
    st = selftest.run()
    if not st["passed"]:
        return False, "Isolation self-test failed — lab execution stays disabled: " + "; ".join(st["failures"])
    return True, ""


def _verify_pinned_commit() -> None:
    src = Path(config.LAB_JUICE_SHOP_DIR)
    out = subprocess.run(["git", "-C", str(src), "rev-parse", "HEAD"],
                        capture_output=True, text=True, timeout=10)
    head = out.stdout.strip()
    if head != config.LAB_JUICE_SHOP_COMMIT:
        raise LabProvisionError(
            f"Pristine checkout HEAD {head!r} does not match the pinned "
            f"LAB_JUICE_SHOP_COMMIT {config.LAB_JUICE_SHOP_COMMIT!r} ({config.LAB_JUICE_SHOP_VERSION}). "
            "Refusing to provision from an unexpected revision.")
    dirty = subprocess.run(["git", "-C", str(src), "status", "--porcelain"],
                           capture_output=True, text=True, timeout=10).stdout.strip()
    if dirty:
        raise LabProvisionError("Pristine checkout has local modifications; refusing to provision from it.")


def _ensure_loopback_patch(instance_dir: Path) -> tuple[bool, str, str]:
    server_js = instance_dir / "build" / "server.js"
    before = server_js.read_bytes()
    before_hash = hashlib.sha256(before).hexdigest()
    if _LISTEN_PATCHED.encode() in before:
        return False, before_hash, before_hash  # already patched (shouldn't happen on a fresh clone)
    if _LISTEN_ORIGINAL.encode() not in before:
        raise LabProvisionError(
            "Could not find the expected server.listen() call to patch for loopback-only "
            "binding — refusing to start unsandboxed-network Juice Shop. This likely means "
            f"the checkout is not {config.LAB_JUICE_SHOP_VERSION} as pinned.")
    after = before.replace(_LISTEN_ORIGINAL.encode(), _LISTEN_PATCHED.encode())
    server_js.write_bytes(after)
    return True, before_hash, hashlib.sha256(after).hexdigest()


def _allocate_ports() -> tuple[int, int]:
    lo, hi = config.LAB_PORT_RANGE_START, config.LAB_PORT_RANGE_END
    free = [p for p in range(lo, hi + 1) if p not in _ports_in_use]
    if len(free) < 2:
        raise LabCapacityReached("No free ports left in LAB_PORT_RANGE.")
    return free[0], free[1]


def _sweep_expired_locked() -> None:
    now = time.time()
    for inst in list(_instances.values()):
        if inst.status in ("ready", "starting") and now - inst.created_at > config.LAB_INSTANCE_TTL_S:
            log_config.audit("lab_ttl_expired", {"instance_id": inst.id})
            _stop(inst)


def list_instances() -> list[dict]:
    with _lock:
        _sweep_expired_locked()
        return [i.public_dict() for i in _instances.values()]


def get_instance(instance_id: str) -> LabInstance | None:
    with _lock:
        return _instances.get(instance_id)


def _stop(inst: LabInstance) -> None:
    if inst.telemetry:
        try:
            inst.telemetry.stop()
        except Exception:
            pass
    if inst.process and inst.process.poll() is None:
        try:
            inst.process.send_signal(signal.SIGTERM)
            inst.process.wait(timeout=5)
        except Exception:
            inst.process.kill()
    inst.status = "stopped"
    _ports_in_use.discard(inst.app_port)
    _ports_in_use.discard(inst.proxy_port)


def _boot_one(scenario_id: str | None) -> LabInstance:
    ok, reason = _lab_enabled()
    if not ok:
        raise LabDisabled(reason)
    _verify_pinned_commit()

    with _lock:
        _sweep_expired_locked()
        live = [i for i in _instances.values() if i.status in ("ready", "starting")]
        if len(live) >= config.LAB_MAX_INSTANCES:
            raise LabCapacityReached(
                f"{config.LAB_MAX_INSTANCES} lab instance(s) already running — "
                "stop or let one expire before starting another.")
        app_port, proxy_port = _allocate_ports()
        _ports_in_use.update((app_port, proxy_port))

    instance_id = uuid.uuid4().hex[:12]
    instance_dir = _INSTANCES_DIR / instance_id
    instance_dir.parent.mkdir(parents=True, exist_ok=True)
    telemetry_path = _TELEMETRY_DIR / f"{instance_id}.jsonl"

    inst = LabInstance(id=instance_id, app_port=app_port, proxy_port=proxy_port,
                       instance_dir=instance_dir, telemetry_path=telemetry_path,
                       created_at=time.time(), scenario_id=scenario_id)
    with _lock:
        _instances[instance_id] = inst

    try:
        subprocess.run(["cp", "-cR", config.LAB_JUICE_SHOP_DIR, str(instance_dir)], check=True,
                       capture_output=True, text=True, timeout=120)
        patched, before_h, after_h = _ensure_loopback_patch(instance_dir)
        inst.patch_applied, inst.patch_before_sha256, inst.patch_after_sha256 = patched, before_h, after_h

        profile_path = instance_dir / ".redbears-sandbox.sb"
        sandbox.write_profile(str(profile_path), work_dir=str(instance_dir),
                              allowed_port=app_port, node_bin_dirs=_NODE_BIN_DIRS)
        node_bin = shutil.which("node") or "/usr/local/bin/node"
        inner = f"ulimit -t 300 2>/dev/null; exec env PORT={app_port} NODE_OPTIONS=--max-old-space-size=512 '{node_bin}' build/app"
        inst.process = subprocess.Popen(
            ["sandbox-exec", "-f", str(profile_path), "/bin/sh", "-c", inner],
            cwd=str(instance_dir), stdout=open(instance_dir / "boot.log", "w"),
            stderr=subprocess.STDOUT, start_new_session=True,
            env={"PATH": "/usr/bin:/bin:/usr/sbin:/sbin:/usr/local/bin:/opt/homebrew/bin",
                 "HOME": str(instance_dir), "TMPDIR": str(instance_dir)})

        deadline = time.time() + config.LAB_BOOT_TIMEOUT_S
        with httpx.Client(timeout=2) as client:
            while time.time() < deadline:
                if inst.process.poll() is not None:
                    raise LabProvisionError("Juice Shop process exited during boot — see boot.log.")
                try:
                    r = client.get(f"http://127.0.0.1:{app_port}/rest/admin/application-version")
                    if r.status_code == 200:
                        break
                except httpx.HTTPError:
                    pass
                time.sleep(1)
            else:
                raise LabProvisionError(f"Juice Shop did not become ready within {config.LAB_BOOT_TIMEOUT_S:g}s.")

        inst.telemetry = TelemetryProxy(listen_port=proxy_port, upstream_port=app_port,
                                        telemetry_path=telemetry_path)
        inst.telemetry.start()
        inst.status = "ready"
        log_config.audit("lab_instance_ready", {"instance_id": instance_id, "scenario_id": scenario_id,
                                                "patch_applied": patched})
        return inst
    except Exception as exc:
        inst.status, inst.error = "error", sandbox_safe_str(exc)
        _stop(inst)
        raise


def sandbox_safe_str(exc: Exception) -> str:
    return f"{type(exc).__name__}: {exc}"[:500]


def create_instance(scenario_id: str | None = None) -> LabInstance:
    return _boot_one(scenario_id)


def reset_instance(instance_id: str) -> LabInstance:
    """Stop + wipe + re-provision in place: same ports, fresh synthetic data,
    fresh telemetry file — the before-state for a detection-improvement rerun."""
    with _lock:
        inst = _instances.get(instance_id)
    if inst is None:
        raise LabProvisionError(f"No such instance {instance_id!r}.")
    scenario_id = inst.scenario_id
    cleanup_instance(instance_id)
    new = create_instance(scenario_id)
    return new


def cleanup_instance(instance_id: str) -> None:
    with _lock:
        inst = _instances.pop(instance_id, None)
    if inst is None:
        return
    _stop(inst)
    shutil.rmtree(inst.instance_dir, ignore_errors=True)
    log_config.audit("lab_instance_cleanup", {"instance_id": instance_id})


def cleanup_all() -> None:
    for iid in list(_instances):
        cleanup_instance(iid)
