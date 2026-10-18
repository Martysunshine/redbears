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

up "http://127.0.0.1:$REDBEARS_RERANK_PORT/v1/models" || nohup "$VENV/bin/python" -m uvicorn server:app --app-dir "$ROOT/rerank_server" \
  --host 127.0.0.1 --port "$REDBEARS_RERANK_PORT" > "$LOGS/rerank.log" 2>&1 &
up "http://127.0.0.1:$REDBEARS_BACKEND_PORT/health" || (cd "$ROOT/oyster/backend" && nohup "$VENV/bin/python" -m uvicorn main:app \
  --host 127.0.0.1 --port "$REDBEARS_BACKEND_PORT" > "$LOGS/backend.log" 2>&1 &)
up "http://127.0.0.1:$REDBEARS_FRONTEND_PORT" || (cd "$ROOT/oyster/frontend" && nohup npx next dev -p "$REDBEARS_FRONTEND_PORT" > "$LOGS/frontend.log" 2>&1 &)

echo "Waiting for services (reranker loads ~2.5 GB on first start)…"
for i in $(seq 1 120); do
  up "http://127.0.0.1:$REDBEARS_BACKEND_PORT/health" && up "http://127.0.0.1:$REDBEARS_FRONTEND_PORT" \
    && up "http://127.0.0.1:$REDBEARS_RERANK_PORT/v1/health/ready" && break; sleep 2; done
echo "Demo:     http://127.0.0.1:$REDBEARS_FRONTEND_PORT   (sidebar → Red Bears)"
echo "Backend:  http://127.0.0.1:$REDBEARS_BACKEND_PORT/health"
echo "Reranker: http://127.0.0.1:$REDBEARS_RERANK_PORT/v1/health/ready"
