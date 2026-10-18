# shellcheck shell=bash
# Shared by the Red Bears scripts. Loads .env (if present) and sets defaults.
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
if [ -f "$ROOT/.env" ]; then set -a; . "$ROOT/.env"; set +a; fi
: "${REDBEARS_ASSETS:=$HOME/redbears-assets}"
: "${REDBEARS_FRONTEND_PORT:=3101}"; : "${REDBEARS_BACKEND_PORT:=8101}"; : "${REDBEARS_RERANK_PORT:=8110}"
VENV="$REDBEARS_ASSETS/venv-backend"
LOGS="$REDBEARS_ASSETS/logs"; mkdir -p "$LOGS"
