"""Standalone server entry: `archon serve`-equivalent for container deployments.

Wires a production-shaped app from environment variables:
    ARCHON_REGISTRY_PATH      SQLite registry file (default /data/registry.db)
    ARCHON_AUDIT_PATH         audit trail file    (default /data/audit.db)
    ARCHON_SPANS_JSONL        optional span sink  (default /data/spans.jsonl)
    ARCHON_UPSTREAM_BASE_URL  default upstream for agents registered without one
    ARCHON_REQUIRE_SIGNED     "1" enforces HMAC-signed requests (default on)

Run: uvicorn archon_armor.server:app --host 0.0.0.0 --port 8080
"""

from __future__ import annotations

import os

from archon_core.audit import SqliteAuditTrail
from archon_core.observability.jsonl import JsonlTracer
from archon_core.observability.scrubbing import AttributeScrubber, ScrubbingTracer
from archon_core.registry.sqlite import SqliteRegistry
from archon_core.security.authn import HmacVerifier
from archon_core.security.ratelimit import TokenBucketRateLimiter
from archon_armor.upstream import HTTPOpenAIUpstream


def build_app():
    registry_path = os.environ.get("ARCHON_REGISTRY_PATH", "/tmp/archon-registry.db")
    audit_path = os.environ.get("ARCHON_AUDIT_PATH", "/tmp/archon-audit.db")
    spans_path = os.environ.get("ARCHON_SPANS_JSONL", "/tmp/archon-spans.jsonl")

    registry = SqliteRegistry(registry_path)
    tracer = ScrubbingTracer(JsonlTracer(spans_path), AttributeScrubber())
    identity = HmacVerifier(registry)  # signed requests enforced in server mode
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
if os.environ.get("ARCHON_SERVER_AUTOSTART", "1") == "1":
    try:
        app = build_app()
    except Exception as exc:  # pragma: no cover - surfaced at startup, not import
        import logging

        logging.getLogger("archon").error("failed to build armor app: %s", exc)
