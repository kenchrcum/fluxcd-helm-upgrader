# syntax=docker/dockerfile:1

# Build stage
FROM alpine:3.22.1 AS builder

# Upgrade system packages
RUN apk upgrade --no-cache

# Install Python and build dependencies
RUN apk add --no-cache \
    python3 \
    py3-pip \
    python3-dev \
    build-base \
    libffi-dev \
    openssl-dev \
    git \
    ca-certificates \
    curl

# Create virtual environment
RUN python3 -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Runtime stage
FROM alpine:3.22.1

# Upgrade system packages
RUN apk upgrade --no-cache

# Install only runtime dependencies
RUN apk add --no-cache \
    python3 \
    ca-certificates \
    curl \
    git \
    openssh-client \
    && rm -rf /var/cache/apk/*

# Copy virtual environment from builder stage
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Set Python environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1

# Upgrade pip
RUN /opt/venv/bin/pip install -U pip

WORKDIR /app

# Copy application code
COPY main.py ./

# Create non-root user and set permissions
RUN addgroup -g 10001 -S appuser && \
    adduser -u 10001 -S appuser -G appuser && \
    chown -R appuser:appuser /app

USER appuser

# Application environment variables
ENV INTERVAL_SECONDS=300 \
    LOG_LEVEL=INFO \
    INCLUDE_PRERELEASE=false

ENTRYPOINT ["python", "-u", "main.py"]
