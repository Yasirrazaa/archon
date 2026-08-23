"""TDD Phase 4: observability — LocalTracer spans, armor request tracing."""

import json

from archon_armor.app import create_app
from archon_core.observability.base import LocalTracer
from archon_core.registry.base import AgentCard, SecurityPolicy
from archon_core.registry.memory import InMemoryRegistry
from fastapi.testclient import TestClient

from .test_app import BENIGN_BODY, INJECTION_BODY, FakeUpstream


def test_local_tracer_records_nested_spans():
    tracer = LocalTracer()
    outer = tracer.start_span("outer", attributes={"a": 1})
    inner = tracer.start_span("inner")
    tracer.end_span(inner, attributes={"b": 2})
    tracer.end_span(outer)

    spans = tracer.spans
    assert [s.name for s in spans] == ["inner", "outer"]  # children complete first
    inner_span = spans[0]
    outer_span = spans[1]
    assert inner_span.parent_id == outer_span.span_id
    assert outer_span.parent_id is None
    assert inner_span.attributes["b"] == 2
    assert outer_span.duration_ms is not None


def test_local_tracer_async_nesting_is_task_safe():
    import asyncio

    tracer = LocalTracer()

    async def child(tracer, name):
        span = tracer.start_span(name)
        await asyncio.sleep(0)
        tracer.end_span(span)

    async def parent(tracer, name):
        span = tracer.start_span(name)
        await asyncio.gather(child(tracer, f"{name}-c1"), child(tracer, f"{name}-c2"))
        tracer.end_span(span)

    async def main():
        await asyncio.gather(parent(tracer, "p1"), parent(tracer, "p2"))

    asyncio.run(main())
    names = {s.name for s in tracer.spans}
    assert names == {"p1", "p2", "p1-c1", "p1-c2", "p2-c1", "p2-c2"}
    # children must attach to their own parent, not a sibling's
    by_id = {s.span_id: s for s in tracer.spans}
    for span in tracer.spans:
        if span.name.endswith("-c1") or span.name.endswith("-c2"):
            parent_name = by_id[span.parent_id].name
            assert span.name.startswith(parent_name)


def test_local_tracer_json_export():
    tracer = LocalTracer()
    span = tracer.start_span("op", attributes={"k": "v"})
    tracer.end_span(span)
    data = json.loads(tracer.to_json())
    assert isinstance(data, list)
    assert data[0]["name"] == "op"
    assert data[0]["attributes"]["k"] == "v"


def _make_traced_client():
    registry = InMemoryRegistry()
    registry.register(
        AgentCard(
            agent_id="agent-1",
            name="t",
            version="1",
            policy=SecurityPolicy(upstream_base_url="https://api.upstream.test/v1"),
        )
    )
    tracer = LocalTracer()
    client = TestClient(create_app(registry=registry, upstream=FakeUpstream(), tracer=tracer))
    return client, tracer


def test_armor_emits_request_and_layer_spans():
    client, tracer = _make_traced_client()
    client.post("/v1/chat/completions", json=BENIGN_BODY, headers={"X-Agent-ID": "agent-1"})

    names = [s.name for s in tracer.spans]
    assert "armor.request" in names
    for layer in ("normalization", "threat_classification", "segmentation", "spotlighting", "execution_mode"):
        assert layer in names
    request_span = next(s for s in tracer.spans if s.name == "armor.request")
    assert request_span.attributes["agent_id"] == "agent-1"
    assert request_span.attributes["blocked"] is False


def test_armor_blocked_request_records_block_reason():
    client, tracer = _make_traced_client()
    client.post("/v1/chat/completions", json=INJECTION_BODY, headers={"X-Agent-ID": "agent-1"})

    request_span = next(s for s in tracer.spans if s.name == "armor.request")
    assert request_span.attributes["blocked"] is True
    assert "threat_classification" in request_span.attributes["block_reason"]
