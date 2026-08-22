"""TDD Phase 8: telemetry hardening — PII scrubbing + streaming JSONL export."""

import json

import pytest

from archon_core.observability.base import LocalTracer
from archon_core.observability.jsonl import JsonlTracer
from archon_core.observability.scrubbing import AttributeScrubber, ScrubbingTracer


class TestAttributeScrubber:
    def test_scrubs_ssn_email_and_keys(self):
        scrubber = AttributeScrubber()
        attrs = {
            "note": "SSN is 123-45-6789",
            "contact": "alice@corp.example.com",
            "auth": "Bearer sk-live-abc123",
            "api_key": "sk-abcdef1234567890",
            "card": "4111 1111 1111 1111",
        }
        cleaned = scrubber.scrub(attrs)
        joined = json.dumps(cleaned)
        for secret in ("123-45-6789", "alice@corp.example.com", "sk-live-abc123",
                       "sk-abcdef1234567890", "4111 1111 1111 1111"):
            assert secret not in joined
        assert "[REDACTED]" in joined or "ssn" in joined.lower()

    def test_scrubbing_is_recursive(self):
        scrubber = AttributeScrubber()
        attrs = {"nested": {"deep": ["bob@corp.example.com"]}}
        assert "bob@corp.example.com" not in json.dumps(scrubber.scrub(attrs))

    def test_non_pii_values_untouched(self):
        scrubber = AttributeScrubber()
        attrs = {"agent_id": "agent-1", "blocked": True, "count": 3}
        assert scrubber.scrub(attrs) == attrs


class TestScrubbingTracer:
    def test_wraps_tracer_and_scrubs_attributes(self):
        inner = LocalTracer()
        tracer = ScrubbingTracer(inner, AttributeScrubber())
        span = tracer.start_span("op", attributes={"who": "leak@corp.example.com"})
        tracer.end_span(span, attributes={"detail": "call 555-123-4567"})

        exported = json.loads(inner.to_json())
        blob = json.dumps(exported)
        assert "leak@corp.example.com" not in blob
        assert "555-123-4567" not in blob


class TestJsonlTracer:
    def test_writes_one_valid_json_object_per_span(self, tmp_path):
        path = tmp_path / "spans.jsonl"
        tracer = JsonlTracer(path)
        s1 = tracer.start_span("outer")
        s2 = tracer.start_span("inner")
        tracer.end_span(s2)
        tracer.end_span(s1)

        lines = path.read_text().strip().splitlines()
        assert len(lines) == 2
        records = [json.loads(line) for line in lines]
        assert [r["name"] for r in records] == ["inner", "outer"]
        assert all("duration_ms" in r for r in records)

    def test_armor_spans_contain_no_response_content(self, tmp_path):
        """Defense-in-depth: upstream content must never reach spans."""
        from fastapi.testclient import TestClient
        from archon_armor.app import create_app
        from archon_core.registry.base import AgentCard, SecurityPolicy
        from archon_core.registry.memory import InMemoryRegistry

        class LeakyUpstream:
            async def complete(self, payload, base_url, api_key=None):
                return {
                    "id": "x", "object": "chat.completion", "model": "m",
                    "choices": [{"index": 0, "finish_reason": "stop",
                                 "message": {"role": "assistant",
                                             "content": "secret: 123-45-6789"}}],
                }

        registry = InMemoryRegistry()
        registry.register(AgentCard(agent_id="a1", name="t", version="1",
                                    policy=SecurityPolicy(upstream_base_url="https://u.test/v1")))
        tracer = JsonlTracer(tmp_path / "spans.jsonl")
        client = TestClient(create_app(registry=registry, upstream=LeakyUpstream(), tracer=tracer))
        client.post("/v1/chat/completions", json={
            "model": "m", "messages": [{"role": "user", "content": "hello"}]
        }, headers={"X-Agent-ID": "a1"})

        blob = (tmp_path / "spans.jsonl").read_text()
        assert "123-45-6789" not in blob
