#!/usr/bin/env bash
# Start the Red Bears stack: Nemotron reranker (8110), Oyster backend (8101), frontend (3101).
# Ollama must already be running (ollama serve / the Ollama app). Logs: $REDBEARS_ASSETS/logs.
set -euo pipefail
. "$(dirname "$0")/lib.sh"
A="$REDBEARS_ASSETS"
export OYSTER_DATA_DIR="$A/data" OYSTER_LOGS_DIR="$LOGS"
export OYSTER_VECTOR_DB_DIR="$A/data/knowledge_snapshot/vector_db"
export OYSTER_MEMORY_DB="$A/data/knowledge_snapshot/memory.db"
export OYSTER_DISABLE_AUTH="${OYSTER_DISABLE_AUTH:-true}" OYSTER_ENVIRONMENT="${OYSTER_ENVIRONMENT:-development}"
export OYSTER_DEFAULT_MODEL="${OYSTER_DEFAULT_MODEL:-oyster-dolphin-v2}" OYSTER_PUBLIC_CHAT_MODEL="${OYSTER_PUBLIC_CHAT_MODEL:-dolphin3}"
export OYSTER_OLLAMA_NUM_CTX="${OYSTER_OLLAMA_NUM_CTX:-8192}" OYSTER_EXECUTION_ENGINE_ENABLED=false
export OYSTER_CORS_ORIGINS="http://localhost:$REDBEARS_FRONTEND_PORT,http://127.0.0.1:$REDBEARS_FRONTEND_PORT"
export NEMOTRON_RERANK_URL="${NEMOTRON_RERANK_URL:-http://127.0.0.1:$REDBEARS_RERANK_PORT/v1/ranking}"
export NEXT_PUBLIC_API_URL="${NEXT_PUBLIC_API_URL:-http://127.0.0.1:$REDBEARS_BACKEND_PORT}" NEXT_PUBLIC_OYSTER_DISABLE_AUTH=true

up() { curl -fs -m 2 "$1" >/dev/null 2>&1; }
curl -fs -m 2 http://127.0.0.1:11434/api/tags >/dev/null || { echo "Ollama is not running on :11434" >&2; exit 1; }

start_service() {
  local name="$1" port="$2" health="$3" cwd="$4"; shift 4
  if up "$health"; then echo "Using existing healthy $name on :$port"; return; fi
  if lsof -tiTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then
    echo "Port $port is occupied but $name is not ready; inspect its log or existing process." >&2; exit 1
  fi
  "$VENV/bin/python" "$ROOT/scripts/service-process.py" start "$LOGS/$name.pid.json" "$cwd" "$LOGS/$name.log" "$@"
}
start_service rerank "$REDBEARS_RERANK_PORT" "http://127.0.0.1:$REDBEARS_RERANK_PORT/v1/models" "$ROOT/rerank_server" \
  "$VENV/bin/python" -m uvicorn server:app --host 127.0.0.1 --port "$REDBEARS_RERANK_PORT"
start_service backend "$REDBEARS_BACKEND_PORT" "http://127.0.0.1:$REDBEARS_BACKEND_PORT/health" "$ROOT/oyster/backend" \
  "$VENV/bin/python" -m uvicorn main:app --host 127.0.0.1 --port "$REDBEARS_BACKEND_PORT"
start_service frontend "$REDBEARS_FRONTEND_PORT" "http://127.0.0.1:$REDBEARS_FRONTEND_PORT" "$ROOT/oyster/frontend" \
  node "$ROOT/oyster/frontend/node_modules/next/dist/bin/next" dev -H 127.0.0.1 -p "$REDBEARS_FRONTEND_PORT"

echo "Waiting for services (reranker loads ~2.5 GB on first start)…"
for i in $(seq 1 120); do
  up "http://127.0.0.1:$REDBEARS_BACKEND_PORT/health" && up "http://127.0.0.1:$REDBEARS_FRONTEND_PORT" \
    && up "http://127.0.0.1:$REDBEARS_RERANK_PORT/v1/health/ready" && break; sleep 2; done
up "http://127.0.0.1:$REDBEARS_BACKEND_PORT/health" && up "http://127.0.0.1:$REDBEARS_FRONTEND_PORT" && up "http://127.0.0.1:$REDBEARS_RERANK_PORT/v1/health/ready" || { echo "Startup incomplete; inspect logs." >&2; exit 1; }
echo "Demo:     http://127.0.0.1:$REDBEARS_FRONTEND_PORT   (sidebar → Red Bears)"
echo "Backend:  http://127.0.0.1:$REDBEARS_BACKEND_PORT/health"
echo "Reranker: http://127.0.0.1:$REDBEARS_RERANK_PORT/v1/health/ready"
