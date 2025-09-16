# syntax=docker/dockerfile:1
FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

# Install runtime deps for kubernetes client (openssh for git if needed later)
RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates curl && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt ./
RUN pip install -r requirements.txt

COPY main.py ./

# Non-root user
RUN useradd -u 10001 -r -g root -s /sbin/nologin -M appuser && chown -R appuser:root /app
USER appuser

ENV INTERVAL_SECONDS=300 \
    LOG_LEVEL=INFO \
    INCLUDE_PRERELEASE=false

ENTRYPOINT ["python", "-u", "main.py"]
