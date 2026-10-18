#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "$ROOT/.." && pwd)"
case "$REPO_ROOT" in
  /tmp/*|/tmp|/private/tmp/*|/private/tmp)
    echo "REFUSING TO RUN: this checkout lives under a temp directory ($REPO_ROOT)." >&2
    exit 1
    ;;
esac

UID_VALUE="$(id -u)"
launchctl bootout "gui/$UID_VALUE/com.redorca.oyster.frontend" 2>/dev/null || true
launchctl bootout "gui/$UID_VALUE/com.redorca.oyster.backend" 2>/dev/null || true
echo "Stopped Oyster frontend and backend launchd agents. Ollama was left running."
