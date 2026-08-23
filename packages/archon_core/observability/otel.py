"""Production OpenTelemetry observability — real SDK spans over OTLP.

OtelTracer adapts Archon's explicit start/end Tracer API onto the OpenTelemetry
SDK so armor request/layer spans export to Cloud Trace, Jaeger, Datadog, or any
OTLP/HTTP collector. Parenting uses a contextvar stack (mirroring LocalTracer)
so concurrent asyncio requests keep independent span trees.

The opentelemetry-sdk import is lazy: archon_core has no hard vendor
dependency. Declare `archon[otel]` (pyproject extra) to enable.
"""

from __future__ import annotations

import contextvars
import json
import os
from typing import Any

from .base import NullTracer, Tracer


def _coerce_value(value: Any) -> Any:
    """OTLP attributes must be primitives or primitive sequences."""
    if value is None or isinstance(value, (str, bool, int, float)):
        return value
    if isinstance(value, (list, tuple)):
        return [_coerce_value(v) for v in value]
    return json.dumps(value, default=str)


def _coerce_attrs(attrs: dict[str, Any] | None) -> dict[str, Any]:
    return {k: _coerce_value(v) for k, v in (attrs or {}).items()}


class OtelTracer(Tracer):
    """Bridge Tracer -> OpenTelemetry SDK with explicit-API parenting."""

    def __init__(self, provider: Any, otel_tracer: Any, stack_var: contextvars.ContextVar) -> None:
        self.provider = provider
        self._tracer = otel_tracer
        self._stack = stack_var

    @classmethod
    def for_exporter(cls, exporter: Any, service_name: str = "archon-armor") -> OtelTracer:
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import SimpleSpanProcessor

        resource = Resource.create({"service.name": service_name})
        provider = TracerProvider(resource=resource)
        # SimpleSpanProcessor keeps tests deterministic; production paths can
        # swap in BatchSpanProcessor without changing this class's contract.
        processor = (
            exporter if hasattr(exporter, "on_start") else SimpleSpanProcessor(exporter)
        )
        if not hasattr(exporter, "on_start"):
            provider.add_span_processor(processor)

        stack_var = contextvars.ContextVar(f"archon_otel_stack_{id(cls)}", default=())
        return cls(provider=provider, otel_tracer=provider.get_tracer("archon"), stack_var=stack_var)

    def start_span(self, name: str, attributes: dict[str, Any] | None = None) -> Any:
        from opentelemetry import trace as otel_trace

        stack = self._stack.get()
        parent_ctx = (
            otel_trace.set_span_in_context(stack[-1]) if stack else None
        )
        span = self._tracer.start_span(
            name, context=parent_ctx, attributes=_coerce_attrs(attributes)
        )
        # Wrap recording span so it participates in parent resolution even
        # though the SDK only exposes contexts through current-span helpers.
        holder = otel_trace.NonRecordingSpan(span.get_span_context())
        holder._archon_recording = span  # type: ignore[attr-defined]
        self._stack.set(stack + (holder,))
        return holder

    def end_span(self, span: Any, attributes: dict[str, Any] | None = None) -> None:
        stack = self._stack.get()
        if stack and stack[-1].get_span_context().span_id == span.get_span_context().span_id:
            self._stack.set(stack[:-1])
        recording = getattr(span, "_archon_recording", None)
        if recording is not None:
            if attributes:
                recording.set_attributes(_coerce_attrs(attributes))
            recording.end()


def _fetch_gcp_token() -> str:
    """Fetch an access token from the GCP metadata server (Cloud Run / GCE).

    Cloud Trace's managed OTLP endpoint (telemetry.googleapis.com) rejects
    unauthenticated writes; the service's identity token authorizes them.
    """
    import json as _json
    import urllib.request as _ur

    req = _ur.Request(
        "http://metadata.google.internal/computeMetadata/v1/instance"
        "/service-accounts/default/token",
        headers={"Metadata-Flavor": "Google"},
    )
    with _ur.urlopen(req, timeout=2) as resp:
        return str(_json.loads(resp.read())["access_token"])


def build_tracer_from_env(env: dict[str, str] | None = None) -> Tracer:
    """Env-driven tracer factory.

    ARCHON_OTEL_EXPORTER: unset/"none" -> NullTracer (zero overhead);
    "memory" -> OtelTracer over InMemorySpanExporter (tests/debug);
    "otlp"   -> OtelTracer over OTLP/HTTP using OTEL_EXPORTER_OTLP_ENDPOINT.
    """
    environ = env if env is not None else os.environ
    mode = environ.get("ARCHON_OTEL_EXPORTER", "none").strip().lower()
    if mode in ("", "none", "off"):
        return NullTracer()

    if mode == "memory":
        from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
            InMemorySpanExporter,
        )

        return OtelTracer.for_exporter(InMemorySpanExporter(), service_name="archon-armor")

    if mode == "otlp":
        import contextvars as cv

        from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
            OTLPSpanExporter,
        )
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor

        endpoint = environ.get("OTEL_EXPORTER_OTLP_ENDPOINT")
        kwargs = {"timeout": 5}
        if endpoint:
            kwargs["endpoint"] = endpoint.rstrip("/") + "/v1/traces"
        if environ.get("ARCHON_OTEL_GCP_AUTH", "") == "1":
            kwargs["headers"] = {"Authorization": f"Bearer {_fetch_gcp_token()}"}
        provider = TracerProvider(
            resource=Resource.create({"service.name": "archon-armor"})
        )
        provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter(**kwargs)))
        return OtelTracer(
            provider=provider,
            otel_tracer=provider.get_tracer("archon"),
            stack_var=cv.ContextVar(f"archon_otel_stack_{id(provider)}", default=()),
        )

    raise ValueError(f"unsupported ARCHON_OTEL_EXPORTER mode: {mode!r}")


__all__ = ["OtelTracer", "build_tracer_from_env"]
