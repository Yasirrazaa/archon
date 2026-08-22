# Archon Armor — production container
FROM python:3.12-slim AS base

WORKDIR /app

# Install the project (packages/* are declared as hatch build targets)
COPY pyproject.toml README.md LICENSE ./
COPY src ./src
COPY packages ./packages
RUN pip install --no-cache-dir .

# Non-root runtime user
RUN useradd -m -u 10001 archon
USER archon

ENV ARCHON_REGISTRY_PATH=/data/registry.db \
    ARCHON_AUDIT_PATH=/data/audit.db \
    ARCHON_SPANS_JSONL=/data/spans.jsonl \
    ARCHON_SERVER_AUTOSTART=1 \
    PYTHONUNBUFFERED=1

VOLUME ["/data"]
EXPOSE 8080

CMD ["uvicorn", "archon_armor.server:app", "--host", "0.0.0.0", "--port", "8080"]
