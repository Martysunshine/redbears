"""Active isolation self-test for the lab sandbox.

Rather than trusting that the Seatbelt profile "should" confine the process,
this runs a Node probe under the SAME profile generator the real lab uses and
tries to do the things a compromised or misdirected lab process must not be
able to do. The lab refuses to provision unless every forbidden probe is
blocked AND the one permitted probe works (so a profile that blocks everything
by accident — and would therefore make the lab silently unusable — also fails).

Probes (all attempted from inside the sandboxed process):
  ALLOWED   connect to the lab's own loopback port                  -> must connect
  FORBIDDEN connect to a different loopback port (stands in for any other
            local service: Oyster itself, Ollama, a database)         -> must be blocked
  FORBIDDEN connect to 1.1.1.1:443 (public internet)                  -> must be blocked
  FORBIDDEN connect to 169.254.169.254:80 (cloud metadata)            -> must be blocked
  FORBIDDEN read a canary file outside its working directory          -> must be blocked
  FORBIDDEN read the user's home dotfiles / project .env              -> must be blocked
  FORBIDDEN write a file outside its working directory                -> must be blocked
  ALLOWED   write inside its working directory                        -> must succeed

The result is cached for the process lifetime; call ``run(force=True)`` after
changing sandbox.py.
"""
from __future__ import annotations

import json
import shutil
import socket
import subprocess
import tempfile
import threading
from pathlib import Path

from services.lab import sandbox

_PROBE_JS = r"""
const net = require('net'), fs = require('fs');
const [ownPort, otherPort, canary, outsideWrite, insideWrite, homeFile] = process.argv.slice(2);
const tcp = (host, port) => new Promise(res => {
  const s = net.connect({host, port: +port, timeout: 2500});
  s.on('connect', () => { s.destroy(); res('reached'); });
  s.on('timeout', () => { s.destroy(); res('blocked'); });
  s.on('error', e => res(e.code === 'ECONNREFUSED' ? 'refused' : 'blocked'));
});
const rd = p => { try { fs.readFileSync(p); return 'read'; } catch (e) { return 'blocked'; } };
const wr = p => { try { fs.writeFileSync(p, 'x'); return 'wrote'; } catch (e) { return 'blocked'; } };
(async () => {
  const out = {
    own_port: await tcp('127.0.0.1', ownPort),
    other_local_port: await tcp('127.0.0.1', otherPort),
    internet: await tcp('1.1.1.1', 443),
    metadata: await tcp('169.254.169.254', 80),
    read_canary: rd(canary), read_home: rd(homeFile),
    write_outside: wr(outsideWrite), write_inside: wr(insideWrite),
  };
  console.log(JSON.stringify(out));
})();
"""

_cached: dict | None = None


def _listener(port_holder: list) -> socket.socket:
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))
    s.listen(8)
    port_holder.append(s.getsockname()[1])
    def _accept_loop() -> None:
        try:
            while True:
                s.accept()[0].close()
        except OSError:
            pass  # listener closed at the end of the run
    threading.Thread(target=_accept_loop, daemon=True).start()
    return s


def run(force: bool = False) -> dict:
    """Returns {"passed": bool, "results": {...}, "failures": [...]} """
    global _cached
    if _cached is not None and not force:
        return _cached
    if not sandbox.available():
        _cached = {"passed": False, "results": {}, "failures": ["sandbox-exec unavailable"]}
        return _cached

    node = shutil.which("node")
    if not node:
        _cached = {"passed": False, "results": {}, "failures": ["node not found"]}
        return _cached

    tmp = Path(tempfile.mkdtemp(prefix="redbears-selftest-")).resolve()
    work = tmp / "work"; work.mkdir()
    outside = tmp / "outside"; outside.mkdir()
    canary = outside / "canary.txt"; canary.write_text("host-secret-canary")
    ports: list = []
    own = _listener(ports); other = _listener(ports)
    own_port, other_port = ports
    home_file = Path.home() / ".zshrc"
    try:
        (work / "probe.js").write_text(_PROBE_JS)
        profile = tmp / "probe.sb"
        sandbox.write_profile(str(profile), work_dir=str(work), allowed_port=own_port,
                              node_bin_dirs=["/usr/local/bin", "/opt/homebrew/bin"])
        proc = subprocess.run(
            ["sandbox-exec", "-f", str(profile), node, str(work / "probe.js"),
             str(own_port), str(other_port), str(canary), str(outside / "written.txt"),
             str(work / "written.txt"), str(home_file)],
            capture_output=True, text=True, timeout=30, cwd=str(work))
        try:
            results = json.loads(proc.stdout.strip().splitlines()[-1])
        except Exception:
            _cached = {"passed": False, "results": {}, "failures": [
                f"probe produced no result (exit {proc.returncode}): {proc.stderr.strip()[:200]}"]}
            return _cached
    finally:
        own.close(); other.close()
        shutil.rmtree(tmp, ignore_errors=True)

    expect = {"own_port": {"reached"}, "other_local_port": {"blocked"}, "internet": {"blocked"},
              "metadata": {"blocked"}, "read_canary": {"blocked"}, "read_home": {"blocked"},
              "write_outside": {"blocked"}, "write_inside": {"wrote"}}
    failures = [f"{k}: got {results.get(k)!r}, expected {sorted(v)}" for k, v in expect.items()
                if results.get(k) not in v]
    _cached = {"passed": not failures, "results": results, "failures": failures}
    return _cached
