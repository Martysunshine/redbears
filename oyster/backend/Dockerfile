# Oyster backend — FastAPI + uvicorn. Multi-stage: build wheels with compilers
# available, run on bare slim. Python 3.11 (not 3.13, unlike Voiceiq's backend)
# for broad wheel availability across chromadb/sentence-transformers/faster-whisper.
#
# Heavy build: sentence-transformers pulls in torch. First `docker compose build`
# on the VPS will take a while and needs real disk/RAM headroom — see
# docs/runbooks/OYSTER_DEPLOY.md's resource-planning step before running this for the first time.
FROM python:3.11-slim AS builder
WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends build-essential \
    && rm -rf /var/lib/apt/lists/*
COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

FROM python:3.11-slim
WORKDIR /app
# ffmpeg: video artifact ingestion (ffprobe/frame sampling). nmap: Execution
# Engine tool (services/execution/tool_registry.py already enforces its
# prohibited-flags guard — --script/-sS/-O stay blocked regardless of the
# binary being present; this deploy restricts who can even reach the
# Execution Engine via OYSTER_ADMIN_EMAILS, so the full tool set is enabled).
# Tesseract OCR is intentionally NOT installed — optional in Oyster's own
# design (config.OCR_ENGINE="auto" falls back to the vision model); add
# `tesseract-ocr` to this list if you want dedicated OCR too.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ffmpeg nmap \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /install /usr/local
COPY . .
EXPOSE 8001
# Secrets + the auth/execution-engine flags come from env_file at runtime (see
# docker-compose.yml) — never baked into the image. .dockerignore keeps
# venv/data/logs/.env out of the build context.
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8001"]
