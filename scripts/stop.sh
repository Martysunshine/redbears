#!/usr/bin/env bash
# Stop only Red Bears' own services (by port). Leaves Ollama and any other project running.
. "$(dirname "$0")/lib.sh"
for p in "$REDBEARS_FRONTEND_PORT" "$REDBEARS_BACKEND_PORT" "$REDBEARS_RERANK_PORT"; do
  pid=$(lsof -tiTCP:"$p" -sTCP:LISTEN 2>/dev/null); [ -n "$pid" ] && kill $pid && echo "stopped :$p"; done
