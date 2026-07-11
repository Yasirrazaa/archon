# Multi-stage Dockerfile for Archon
# Stage 1: Builder - install dependencies
FROM python:3.11-slim AS builder

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Install uv for fast package management
COPY --from=ghcr.io/astral-sh/uv:latest /uv /usr/local/bin/uv

# Copy project files
COPY pyproject.toml uv.lock ./
COPY src/archon ./src/archon
COPY scenarios ./scenarios

# Install dependencies
RUN uv sync --frozen --no-dev --no-install-project

# Stage 2: Runtime - minimal image
FROM python:3.11-slim AS runtime

WORKDIR /app

# Create non-root user
RUN groupadd -r archon && useradd -r -g archon -d /app -s /sbin/nologin archon

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy installed packages from builder
COPY --from=builder /app/.venv /app/.venv

# Copy project source
COPY --from=builder /app/src/archon ./src/archon
COPY --from=builder /app/scenarios ./scenarios
COPY pyproject.toml ./

# Set PATH to use venv
ENV PATH="/app/.venv/bin:$PATH"

# Change ownership to non-root user
RUN chown -R archon:archon /app

# Switch to non-root user
USER archon

# Default command (overridden by docker-compose)
CMD ["python", "-m", "archon.client_cli", "--help"]