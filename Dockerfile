# Archon Armor — production container
FROM python:3.12-slim AS base

WORKDIR /app

# Install the project (packages/* are declared as hatch build targets).
# Extras: otel = OTLP/Cloud Trace span export; postgres = PostgresRegistry.
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
COPY packages ./packages
# AgentBeats defender modules loaded by archon_core.compat at runtime
# (repo-relative in dev; resolved via cwd/sys.prefix in the container).
COPY scenarios ./scenarios
RUN pip install --no-cache-dir ".[otel,postgres]"

# Non-root runtime user
RUN useradd -m -u 10001 archon
# /data must exist and be writable by the runtime user BEFORE VOLUME is
# declared, otherwise Docker auto-creates the volume root-owned and the
# non-root process cannot create audit.db / registry.db inside it.
RUN mkdir -p /data && chown -R archon:archon /data
USER archon

ENV ARCHON_REGISTRY_PATH=/data/registry.db \
    ARCHON_AUDIT_PATH=/data/audit.db \
    ARCHON_SPANS_JSONL=/data/spans.jsonl \
    ARCHON_SERVER_AUTOSTART=1 \
    PYTHONUNBUFFERED=1

VOLUME ["/data"]
EXPOSE 8080

CMD ["uvicorn", "archon_armor.server:app", "--host", "0.0.0.0", "--port", "8080"]
