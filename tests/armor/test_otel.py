"""Sprint A2 — real OpenTelemetry SDK observability.

OtelTracer bridges Archon's explicit Tracer API onto the OpenTelemetry SDK so
armor spans land in Cloud Trace / Jaeger / any OTLP collector. The SDK import
is lazy: archon_core stays importable (and testable) without opentelemetry
installed; declare the `otel` extra instead.
"""

from __future__ import annotations

import time

import pytest

from archon_core.observability.base import NullTracer, Tracer


@pytest.fixture()
def memory_exporter():
    from opentelemetry.sdk.trace.export.in_memory_span_exporter import (
        InMemorySpanExporter,
    )

    return InMemorySpanExporter()


@pytest.fixture()
def otel_tracer(memory_exporter):
    from archon_core.observability.otel import OtelTracer

    return OtelTracer.for_exporter(memory_exporter, service_name="archon-test")


def _flush(otel_tracer, memory_exporter):
    provider = otel_tracer.provider
    provider.force_flush(timeout_millis=5000)
    return memory_exporter.get_finished_spans()


def test_otel_tracer_satisfies_tracer_abc(otel_tracer):
    assert isinstance(otel_tracer, Tracer)


def test_exports_span_with_name_and_attributes(otel_tracer, memory_exporter):
    span = otel_tracer.start_span("armor.request", {"agent_id": "support-bot"})
    otel_tracer.end_span(span, {"verdict": "allowed"})

    exported = _flush(otel_tracer, memory_exporter)
    assert len(exported) == 1
    rec = exported[0]
    assert rec.name == "armor.request"
    attrs = dict(rec.attributes)
    assert attrs["agent_id"] == "support-bot"
    assert attrs["verdict"] == "allowed"


def test_parent_child_nesting_preserved(otel_tracer, memory_exporter):
    root = otel_tracer.start_span("armor.request")
    child = otel_tracer.start_span("defense.layer", {"layer": "L1"})
    otel_tracer.end_span(child, {"verdict": "blocked"})
    otel_tracer.end_span(root)

    exported = _flush(otel_tracer, memory_exporter)
    by_name = {s.name: s for s in exported}
    assert by_name["defense.layer"].parent.span_id == by_name["armor.request"].context.span_id


def test_concurrent_tasks_get_independent_trees(otel_tracer, memory_exporter):
    import asyncio

    async def branch(tag: str):
        outer = otel_tracer.start_span(f"outer.{tag}")
        inner = otel_tracer.start_span(f"inner.{tag}")
        await asyncio.sleep(0)  # yield mid-tree like real async pipelines do
        otel_tracer.end_span(inner)
        otel_tracer.end_span(outer)

    async def run():
        await asyncio.gather(branch("a"), branch("b"))

    asyncio.run(run())

    exported = _flush(otel_tracer, memory_exporter)
    by_name = {s.name: s for s in exported}
    assert by_name["inner.a"].parent.span_id == by_name["outer.a"].context.span_id
    assert by_name["inner.b"].parent.span_id == by_name["outer.b"].context.span_id


def test_non_primitive_attributes_json_encoded(otel_tracer, memory_exporter):
    span = otel_tracer.start_span("probe.run")
    otel_tracer.end_span(
        span, {"payload": {"nested": ["a", 1]}, "tags": ["x", "y"], "n": 3}
    )

    exported = _flush(otel_tracer, memory_exporter)
    attrs = dict(exported[0].attributes)
    assert '"nested"' in attrs["payload"]  # dict became JSON string
    assert list(attrs["tags"]) == ["x", "y"]
    assert attrs["n"] == 3


def test_duration_is_positive(otel_tracer, memory_exporter):
    span = otel_tracer.start_span("timed")
    time.sleep(0.005)
    otel_tracer.end_span(span)

    exported = _flush(otel_tracer, memory_exporter)
    assert (exported[0].end_time - exported[0].start_time) > 0


# ---------------------------------------------------------------- factory ---


def test_factory_default_is_null(monkeypatch):
    from archon_core.observability.otel import build_tracer_from_env

    monkeypatch.delenv("ARCHON_OTEL_EXPORTER", raising=False)
    assert isinstance(build_tracer_from_env(), NullTracer)


def test_factory_memory_mode(monkeypatch):
    from archon_core.observability.otel import OtelTracer, build_tracer_from_env

    monkeypatch.setenv("ARCHON_OTEL_EXPORTER", "memory")
    tracer = build_tracer_from_env()
    assert isinstance(tracer, OtelTracer)


def test_factory_otlp_mode_builds_without_sending(monkeypatch):
    from archon_core.observability.otel import OtelTracer, build_tracer_from_env

    monkeypatch.setenv("ARCHON_OTEL_EXPORTER", "otlp")
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:4318")
    tracer = build_tracer_from_env()
    assert isinstance(tracer, OtelTracer)


def test_factory_unknown_mode_raises(monkeypatch):
    from archon_core.observability.otel import build_tracer_from_env

    monkeypatch.setenv("ARCHON_OTEL_EXPORTER", "carrier-pigeon")
    with pytest.raises(ValueError, match="ARCHON_OTEL_EXPORTER"):
        build_tracer_from_env()


def test_factory_otlp_gcp_auth_attaches_metadata_token(monkeypatch):
    """ARCHON_OTEL_GCP_AUTH=1 fetches an identity token from the GCP metadata
    server and attaches it to every OTLP export — required for Cloud Trace's
    managed OTLP endpoint (telemetry.googleapis.com), which rejects
    unauthenticated writes."""
    import archon_core.observability.otel as otel_mod

    captured: dict = {}

    class FakeExporter:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        def export(self, spans):
            return 0

        def shutdown(self):
            return None

    monkeypatch.setattr(otel_mod, "_fetch_gcp_token", lambda: "fake-token")
    monkeypatch.setattr(
        "opentelemetry.exporter.otlp.proto.http.trace_exporter.OTLPSpanExporter",
        FakeExporter,
    )
    monkeypatch.setenv("ARCHON_OTEL_EXPORTER", "otlp")
    monkeypatch.setenv("ARCHON_OTEL_GCP_AUTH", "1")
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "https://telemetry.googleapis.com")

    tracer = otel_mod.build_tracer_from_env()
    assert isinstance(tracer, otel_mod.OtelTracer)
    assert captured["endpoint"] == "https://telemetry.googleapis.com/v1/traces"
    assert captured["headers"]["Authorization"] == "Bearer fake-token"


def test_factory_otlp_without_gcp_auth_sends_no_headers(monkeypatch):
    import archon_core.observability.otel as otel_mod

    captured: dict = {}

    class FakeExporter:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        def export(self, spans):
            return 0

        def shutdown(self):
            return None

    monkeypatch.setattr(
        "opentelemetry.exporter.otlp.proto.http.trace_exporter.OTLPSpanExporter",
        FakeExporter,
    )
    monkeypatch.setenv("ARCHON_OTEL_EXPORTER", "otlp")
    monkeypatch.delenv("ARCHON_OTEL_GCP_AUTH", raising=False)
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://127.0.0.1:4318")

    otel_mod.build_tracer_from_env()
    assert "headers" not in captured


# ------------------------------------------------------------ server wire ---


def test_server_wires_otel_tracer(monkeypatch, tmp_path):
    from archon_core.observability.otel import OtelTracer
    from archon_core.observability.scrubbing import ScrubbingTracer

    monkeypatch.setenv("ARCHON_REGISTRY_PATH", str(tmp_path / "reg.db"))
    monkeypatch.setenv("ARCHON_AUDIT_PATH", str(tmp_path / "audit.db"))
    monkeypatch.setenv("ARCHON_SPANS_JSONL", str(tmp_path / "spans.jsonl"))
    monkeypatch.setenv("ARCHON_SERVER_AUTOSTART", "0")
    monkeypatch.setenv("ARCHON_OTEL_EXPORTER", "memory")

    from archon_armor import server

    app = server.build_app()
    # tracer reachable through the request handler state
    tracer = app.state.tracer
    assert isinstance(tracer, ScrubbingTracer)
    inner = tracer._inner
    while hasattr(inner, "_inner"):
        inner = inner._inner
    assert isinstance(inner, OtelTracer)
