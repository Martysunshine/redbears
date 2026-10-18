# Red Bears IDOR demo lab — minimal image for the disposable target.
# One image serves either mode; LAB_MODE (set per compose service) chooses.
FROM python:3.11-slim

# Don't buffer logs; no .pyc clutter.
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

WORKDIR /app

# Install deps first for layer caching. Copy just the lab package.
COPY requirements.txt /app/lab/requirements.txt
RUN pip install --no-cache-dir -r /app/lab/requirements.txt

COPY __init__.py app.py fixtures.py /app/lab/

# Run as a non-root user — the target never needs privileges.
RUN useradd --create-home --uid 10001 labuser
USER labuser

# LAB_MODE is supplied by the compose service (vulnerable | patched).
ENV LAB_MODE=vulnerable

# Binds 0.0.0.0 *inside the container only*. The host never publishes this
# except on loopback (see docker-compose.yml). 8000 is the in-container port.
EXPOSE 8000
CMD ["uvicorn", "lab.app:app", "--host", "0.0.0.0", "--port", "8000"]
