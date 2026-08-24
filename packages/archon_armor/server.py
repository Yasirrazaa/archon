"""Standalone server entry: `archon serve`-equivalent for container deployments.

Wires a production-shaped app from environment variables:
    ARCHON_REGISTRY_PATH      SQLite registry file (default /data/registry.db)
    ARCHON_DATABASE_URL       Postgres DSN — when set, uses PostgresRegistry (enterprise)
    ARCHON_AUDIT_PATH         audit trail file    (default /data/audit.db)
    ARCHON_SPANS_JSONL        optional span sink  (default /data/spans.jsonl)
    ARCHON_OTEL_EXPORTER      none|memory|otlp    (default none)
    OTEL_EXPORTER_OTLP_ENDPOINT  collector URL for otlp mode (e.g. Cloud Trace)
    ARCHON_UPSTREAM_BASE_URL  default upstream for agents registered without one
    ARCHON_REQUIRE_SIGNED     "1" enforces HMAC-signed requests (default on)

Run: uvicorn archon_armor.server:app --host 0.0.0.0 --port 8080
"""

from __future__ import annotations

import os

from archon_core.audit import SqliteAuditTrail
from archon_core.observability.base import NullTracer
from archon_core.observability.jsonl import JsonlTracer
from archon_core.observability.otel import build_tracer_from_env
from archon_core.observability.scrubbing import AttributeScrubber, ScrubbingTracer
from archon_core.registry.sqlite import SqliteRegistry
from archon_core.security.authn import HmacVerifier, NonceStore
from archon_core.security.ratelimit import TokenBucketRateLimiter

from archon_armor.upstream import HTTPOpenAIUpstream


def build_app():
    registry_path = os.environ.get("ARCHON_REGISTRY_PATH", "/tmp/archon-registry.db")
    audit_path = os.environ.get("ARCHON_AUDIT_PATH", "/tmp/archon-audit.db")
    spans_path = os.environ.get("ARCHON_SPANS_JSONL", "/tmp/archon-spans.jsonl")

    database_url = os.environ.get("ARCHON_DATABASE_URL", "")
    if database_url:
        from archon_core.registry.postgres import PostgresRegistry

        registry = PostgresRegistry(dsn=database_url)
    else:
        registry = SqliteRegistry(registry_path)
    # OTel mode (ARCHON_OTEL_EXPORTER=otlp|memory) takes precedence; default
    # remains the streaming JSONL sink so containers work with zero config.
    base_tracer = build_tracer_from_env()
    if isinstance(base_tracer, NullTracer):
        base_tracer = JsonlTracer(spans_path)
    tracer = ScrubbingTracer(base_tracer, AttributeScrubber())
    # Signed requests enforced; nonce store closes the within-window replay
    # gap (clients must send a fresh X-Nonce per request).
    identity = HmacVerifier(registry, nonce_store=NonceStore())
    rate_limiter = TokenBucketRateLimiter(capacity=60, refill_per_second=10)
    audit = SqliteAuditTrail(audit_path)

    from archon_armor.app import create_app

    return create_app(
        registry=registry,
        upstream=HTTPOpenAIUpstream(),
        tracer=tracer,
        identity=identity,
        rate_limiter=rate_limiter,
        audit=audit,
    )


# Module-level app for `uvicorn archon_armor.server:app`
app = None


def initialize_app() -> None:
    """Build the app eagerly and fail fast.

    A container whose dependencies are misconfigured must crash on startup —
    Cloud Run (and any orchestrator with a startup probe) rejects the revision
    — instead of silently serving 500s as an ``app = None`` zombie.
    """
    global app
    if os.environ.get("ARCHON_SERVER_AUTOSTART", "1") == "1":
        app = build_app()


initialize_app()
