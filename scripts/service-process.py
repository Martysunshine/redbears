#!/usr/bin/env python3
"""Launch detached service groups; stop only recorded, identity-checked groups."""
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time


def identity(pid):
    r = subprocess.run(['ps', '-p', str(pid), '-o', 'lstart='], capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 else ''


def main():
    action, state_path, *args = sys.argv[1:]
    state = Path(state_path)
    if action == 'start':
        cwd, log, *cmd = args
        if state.exists():
            old = json.loads(state.read_text())
            if identity(old['pid']) == old['started']:
                raise SystemExit('Recorded service is still running; stop it before restarting.')
        with open(log, 'ab', buffering=0) as out:
            p = subprocess.Popen(cmd, cwd=cwd, stdin=subprocess.DEVNULL, stdout=out, stderr=out, start_new_session=True)
        started = identity(p.pid)
        if not started:
            raise SystemExit('Service exited during startup; inspect its log.')
        state.write_text(json.dumps({'pid': p.pid, 'started': started}))
        state.chmod(0o600)
        print(f'Started {state.stem} (PID {p.pid}).')
    elif action == 'stop':
        if not state.exists():
            print(f'No owned {state.stem} process recorded; leaving existing listeners alone.')
            return
        record = json.loads(state.read_text()); pid = record['pid']
        if identity(pid) != record['started']:
            state.unlink()
            print(f'{state.stem}: stale PID record; no process signalled.')
            return
        if os.getpgid(pid) != pid:
            raise SystemExit('Process group identity changed; refusing to stop it.')
        os.killpg(pid, signal.SIGTERM)
        # Do not force-kill: backend shutdown must clean up lab instances.
        for _ in range(100):
            if not identity(pid):
                state.unlink(missing_ok=True)
                print(f'Stopped {state.stem}.')
                return
            time.sleep(.1)
        raise SystemExit(f'{state.stem} is still shutting down; no force-kill sent.')
    else:
        raise SystemExit('Expected start or stop.')

if __name__ == '__main__':
    main()
