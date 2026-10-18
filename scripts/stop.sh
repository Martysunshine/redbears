#!/usr/bin/env bash
# Stop only identity-checked service groups launched by scripts/start.sh.
set -euo pipefail
. "$(dirname "$0")/lib.sh"
for name in frontend backend rerank; do
  "$VENV/bin/python" "$ROOT/scripts/service-process.py" stop "$LOGS/$name.pid.json"
done
