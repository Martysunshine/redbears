#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "$ROOT/.." && pwd)"

# This checkout must be durable. A previous copy of this stack was launched
# from /private/tmp and lost 94.6% of its tracked files to OS temp cleanup
# while still running (see oyster/docs/AI_HANDOFF.md) — refuse to repeat that.
case "$REPO_ROOT" in
  /tmp/*|/tmp|/private/tmp/*|/private/tmp)
    echo "REFUSING TO START: this checkout lives under a temp directory ($REPO_ROOT)." >&2
    echo "Temp directories are cleared by OS maintenance without warning, even while a" >&2
    echo "long-lived server keeps running against them. Use a durable checkout/worktree" >&2
    echo "(e.g. ~/oyster-integration) instead." >&2
    exit 1
    ;;
esac

BACKEND="$ROOT/backend"
FRONTEND="$ROOT/frontend"
KNOWLEDGE_SNAPSHOT="$BACKEND/data/knowledge_snapshot"
STATE_DIR="${TMPDIR:-/tmp}/oyster-local"
AGENT_DIR="$HOME/Library/LaunchAgents"
UID_VALUE="$(id -u)"
mkdir -p "$STATE_DIR" "$AGENT_DIR"
is_up() { curl -fsS --max-time 3 "$1" >/dev/null 2>&1; }
port_pid() { lsof -tiTCP:"$1" -sTCP:LISTEN 2>/dev/null | head -1; }

# --- Explicit launcher ownership -------------------------------------------
# Two checkouts (e.g. oyster-integration and oyster-app-hardening) ship this
# same launcher and write the SAME LaunchAgents plists, so whoever starts last
# silently replaces the running stack — which already happened once (a build
# without the CSP fix took over and the app fell back to anonymous). Record the
# owning checkout and refuse to clobber a DIFFERENT owner while its stack is up,
# unless the operator explicitly opts in. This makes a takeover deliberate and
# visible instead of silent. The sibling checkout must run this same guarded
# launcher for the protection to be mutual (it is the same tracked file).
OWNER_FILE="$STATE_DIR/owner"
CURRENT_OWNER="$(cat "$OWNER_FILE" 2>/dev/null || true)"
if [ -n "$CURRENT_OWNER" ] && [ "$CURRENT_OWNER" != "$REPO_ROOT" ] \
   && [ "${OYSTER_LAUNCH_TAKEOVER:-0}" != "1" ] \
   && { is_up http://127.0.0.1:8001/health || is_up http://127.0.0.1:3001; }; then
  echo "REFUSING TO START: the local Oyster stack is owned by a DIFFERENT checkout:" >&2
  echo "    owner : $CURRENT_OWNER" >&2
  echo "    this  : $REPO_ROOT" >&2
  echo "Starting here would replace the running services. If that is intended, re-run:" >&2
  echo "    OYSTER_LAUNCH_TAKEOVER=1 $0" >&2
  exit 3
fi

is_up http://127.0.0.1:11434/api/tags || { echo "Ollama is not responding on 127.0.0.1:11434" >&2; exit 1; }

BACKEND_PYTHON="$BACKEND/venv/bin/python"
if [ ! -x "$BACKEND_PYTHON" ]; then
  echo "Backend venv missing at $BACKEND_PYTHON" >&2
  echo "Run: cd $BACKEND && python3 -m venv venv && venv/bin/pip install -r requirements.txt" >&2
  exit 1
fi
NODE_BIN="$(command -v node)"
if [ -z "$NODE_BIN" ]; then
  echo "node not found on PATH" >&2
  exit 1
fi
if [ ! -d "$FRONTEND/.next" ]; then
  echo "Frontend has no production build at $FRONTEND/.next" >&2
  echo "Run: cd $FRONTEND && npm run build" >&2
  exit 1
fi
if [ ! -f "$KNOWLEDGE_SNAPSHOT/memory.db" ] || [ ! -f "$KNOWLEDGE_SNAPSHOT/vector_db/chroma.sqlite3" ]; then
  echo "Knowledge snapshot missing at $KNOWLEDGE_SNAPSHOT" >&2
  echo "Provision a copy-on-write snapshot from the integration checkout before starting." >&2
  exit 1
fi

BACKEND_PLIST="$AGENT_DIR/com.redorca.oyster.backend.plist"
FRONTEND_PLIST="$AGENT_DIR/com.redorca.oyster.frontend.plist"

cat >"$BACKEND_PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>com.redorca.oyster.backend</string>
<key>ProgramArguments</key><array><string>$BACKEND_PYTHON</string><string>-m</string><string>uvicorn</string><string>main:app</string><string>--host</string><string>127.0.0.1</string><string>--port</string><string>8001</string></array>
<key>WorkingDirectory</key><string>$BACKEND</string>
<key>EnvironmentVariables</key><dict><key>OYSTER_ENVIRONMENT</key><string>development</string><key>OYSTER_DISABLE_AUTH</key><string>true</string><key>OYSTER_EXECUTION_ENGINE_ENABLED</key><string>false</string><key>OYSTER_ANON_CHAT_DAILY_LIMIT</key><string>1000</string><key>OLLAMA_BASE_URL</key><string>http://127.0.0.1:11434</string><key>OLLAMA_HOST</key><string>127.0.0.1</string><key>OLLAMA_PORT</key><string>11434</string><key>OYSTER_DEFAULT_MODEL</key><string>oyster-dolphin-v2</string><key>OYSTER_PUBLIC_CHAT_MODEL</key><string>dolphin3</string><key>OYSTER_CORS_ORIGINS</key><string>http://localhost:3001,http://127.0.0.1:3001</string><key>OYSTER_OLLAMA_NUM_CTX</key><string>8192</string><key>OYSTER_MEMORY_DB</key><string>$KNOWLEDGE_SNAPSHOT/memory.db</string><key>OYSTER_VECTOR_DB_DIR</key><string>$KNOWLEDGE_SNAPSHOT/vector_db</string></dict>
<key>StandardOutPath</key><string>$STATE_DIR/backend.log</string><key>StandardErrorPath</key><string>$STATE_DIR/backend.log</string><key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
</dict></plist>
EOF
cat >"$FRONTEND_PLIST" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>com.redorca.oyster.frontend</string>
<key>ProgramArguments</key><array><string>$NODE_BIN</string><string>$FRONTEND/node_modules/next/dist/bin/next</string><string>start</string><string>--hostname</string><string>127.0.0.1</string><string>--port</string><string>3001</string></array>
<key>WorkingDirectory</key><string>$FRONTEND</string><key>EnvironmentVariables</key><dict><key>NEXT_PUBLIC_API_URL</key><string>http://127.0.0.1:8001</string><key>NEXT_PUBLIC_OYSTER_DISABLE_AUTH</key><string>true</string></dict>
<key>StandardOutPath</key><string>$STATE_DIR/frontend.log</string><key>StandardErrorPath</key><string>$STATE_DIR/frontend.log</string><key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
</dict></plist>
EOF

launchctl bootout "gui/$UID_VALUE/com.redorca.oyster.backend" 2>/dev/null || true
launchctl bootout "gui/$UID_VALUE/com.redorca.oyster.frontend" 2>/dev/null || true
launchctl bootstrap "gui/$UID_VALUE" "$BACKEND_PLIST"
launchctl bootstrap "gui/$UID_VALUE" "$FRONTEND_PLIST"
for _ in $(seq 1 60); do
  if is_up http://127.0.0.1:11434/api/tags && is_up http://127.0.0.1:8001/health && is_up http://127.0.0.1:3001; then
    port_pid 8001 >"$STATE_DIR/backend.pid"; port_pid 3001 >"$STATE_DIR/frontend.pid"; port_pid 11434 >"$STATE_DIR/ollama.pid"
    printf '%s\n' "$REPO_ROOT" > "$OWNER_FILE"   # this checkout now owns the stack
    printf 'Oyster ready: http://127.0.0.1:3001\nowner=%s\nmodel=oyster-dolphin-v2 (signed-in default, GGUF; oyster-dolphin-v1 + dolphin3 selectable as rollback; dolphin3 = anonymous; Edge models experimental)\nbackend_pid=%s frontend_pid=%s ollama_pid=%s\n' "$REPO_ROOT" "$(cat "$STATE_DIR/backend.pid")" "$(cat "$STATE_DIR/frontend.pid")" "$(cat "$STATE_DIR/ollama.pid")"
    exit 0
  fi
  sleep 1
done
echo "Oyster did not become healthy; see $STATE_DIR/*.log" >&2
exit 1
