"""Sprint 85: wire ActionReminderLayer + ToolCallRail into the armor request pipeline."""

from archon_armor.app import _build_request_pipeline, create_app
from archon_core.defenses.action_reminder import (
    REMINDER_MARKER,
    ActionReminderLayer,
    PolicyReminder,
)
from archon_core.defenses.tool_rail import ToolCallRail, ToolSpec
from archon_core.registry.base import AgentCard, SecurityPolicy
from archon_core.registry.memory import InMemoryRegistry
from fastapi.testclient import TestClient

BASE_LAYER_NAMES = [
    "normalization",
    "threat_classification",
    "segmentation",
    "spotlighting",
    "execution_mode",
]

TOOL_SCHEMAS = [
    {
        "name": "search",
        "parameters_schema": {
            "type": "object",
            "properties": {"query": {"type": "string"}},
            "required": ["query"],
            "additionalProperties": False,
        },
    }
]

REMINDERS = [
    PolicyReminder(
        trigger=r"delete\s+all\s+records",
        reminder="Deletion requires manager approval ticket.",
    )
]


def _policy(**extra_kwargs) -> SecurityPolicy:
    return SecurityPolicy(upstream_base_url="https://api.upstream.test/v1", **extra_kwargs)


class FakeUpstream:
    def __init__(self, content="Sure, happy to help!"):
        self.calls = []
        self.content = content

    async def complete(self, payload: dict, base_url: str, api_key: str | None = None):
        self.calls.append(payload)
        last_user = next(
            (m["content"] for m in reversed(payload["messages"]) if m["role"] == "user"),
            "",
        )
        return {
            "id": "chatcmpl-fake",
            "object": "chat.completion",
            "model": payload.get("model", "test-model"),
            "choices": [
                {
                    "index": 0,
                    "finish_reason": "stop",
                    "message": {"role": "assistant", "content": f"{self.content} ({last_user[:20]})"},
                }
            ],
        }


def _make_client(policy=None, registry=None, upstream=None, **app_kwargs):
    registry = registry or InMemoryRegistry()
    registry.register(
        AgentCard(
            agent_id="agent-1",
            name="Test Agent",
            version="1.0.0",
            capabilities=["chat"],
            policy=policy or _policy(),
        )
    )
    upstream = upstream or FakeUpstream()
    app = create_app(registry=registry, upstream=upstream, **app_kwargs)
    return TestClient(app), upstream


# --- builder-level tests ------------------------------------------------------


def test_default_pipeline_unchanged_without_kwargs():
    """No tool rail / reminder layer unless explicitly configured."""
    pipeline = _build_request_pipeline(_policy(), None)
    assert [layer.name for layer in pipeline.layers] == BASE_LAYER_NAMES


def test_tool_rail_appended_from_policy_tool_schemas():
    policy = _policy(extra={"tool_schemas": TOOL_SCHEMAS})
    pipeline = _build_request_pipeline(policy, None)
    assert [layer.name for layer in pipeline.layers] == BASE_LAYER_NAMES + ["tool_rail"]
    rail = pipeline.layers[-1]
    assert isinstance(rail, ToolCallRail)
    assert [spec.name for spec in rail.specs] == ["search"]


def test_no_tool_rail_when_policy_has_no_tool_schemas():
    policy = _policy(extra={"unrelated": True})
    pipeline = _build_request_pipeline(policy, None)
    assert all(not isinstance(layer, ToolCallRail) for layer in pipeline.layers)


def test_tool_rail_kwarg_passthrough():
    custom_rail = ToolCallRail([ToolSpec(name="custom_tool")])
    pipeline = _build_request_pipeline(_policy(), None, tool_rail=custom_rail)
    assert pipeline.layers[-1] is custom_rail


def test_empty_policy_tool_schemas_adds_no_rail():
    policy = _policy(extra={"tool_schemas": []})
    pipeline = _build_request_pipeline(policy, None)
    assert [layer.name for layer in pipeline.layers] == BASE_LAYER_NAMES


def test_action_reminder_layer_appended_when_configured():
    pipeline = _build_request_pipeline(_policy(), None, reminders=REMINDERS)
    assert [layer.name for layer in pipeline.layers] == BASE_LAYER_NAMES + ["action_reminder"]
    assert isinstance(pipeline.layers[-1], ActionReminderLayer)


def test_no_action_reminder_layer_by_default():
    pipeline = _build_request_pipeline(_policy(extra={"tool_schemas": TOOL_SCHEMAS}), None)
    names = [layer.name for layer in pipeline.layers]
    assert names == BASE_LAYER_NAMES + ["tool_rail"]


def test_both_layers_ordered_tool_rail_then_reminder():
    policy = _policy(extra={"tool_schemas": TOOL_SCHEMAS})
    pipeline = _build_request_pipeline(policy, None, reminders=REMINDERS)
    assert [layer.name for layer in pipeline.layers] == BASE_LAYER_NAMES + [
        "tool_rail",
        "action_reminder",
    ]


# --- end-to-end pipeline-context tests ----------------------------------------


BENIGN_BODY = {
    "model": "gpt-test",
    "messages": [{"role": "user", "content": "What is the weather tomorrow?"}],
}

REMINDER_BODY = {
    "model": "gpt-test",
    "messages": [{"role": "user", "content": "Please delete all records for tenant X."}],
}


def test_reminder_mutates_not_blocks_in_live_pipeline():
    client, upstream = _make_client(reminders=REMINDERS)
    resp = client.post(
        "/v1/chat/completions", json=REMINDER_BODY, headers={"X-Agent-ID": "agent-1"}
    )
    assert resp.status_code == 200
    assert resp.headers.get("x-archon-blocked") != "true"
    forwarded_content = upstream.calls[0]["messages"][-1]["content"]
    assert REMINDER_MARKER in forwarded_content
    assert "manager approval ticket" in forwarded_content


def test_reminder_absent_when_not_configured():
    client, upstream = _make_client()
    resp = client.post(
        "/v1/chat/completions", json=REMINDER_BODY, headers={"X-Agent-ID": "agent-1"}
    )
    assert resp.status_code == 200
    assert REMINDER_MARKER not in upstream.calls[0]["messages"][-1]["content"]


def test_tool_rail_blocks_invalid_emitted_call_in_pipeline():
    policy = _policy(extra={"tool_schemas": TOOL_SCHEMAS})
    client, upstream = _make_client(policy=policy)
    body = {
        **BENIGN_BODY,
        "tool_calls": [{"name": "unknown_tool", "args": {"query": "x"}}],
    }
    resp = client.post(
        "/v1/chat/completions", json=body, headers={"X-Agent-ID": "agent-1"}
    )
    assert resp.status_code == 200
    assert resp.headers.get("x-archon-blocked") == "true"
    assert resp.json()["archon"]["block_reason"].startswith("tool_rail:")
    assert not upstream.calls


def test_valid_tool_call_passes_through_rail():
    policy = _policy(extra={"tool_schemas": TOOL_SCHEMAS})
    client, upstream = _make_client(policy=policy)
    body = {
        **BENIGN_BODY,
        "tool_calls": [{"name": "search", "args": {"query": "weather"}}],
    }
    resp = client.post(
        "/v1/chat/completions", json=body, headers={"X-Agent-ID": "agent-1"}
    )
    assert resp.status_code == 200
    assert resp.headers.get("x-archon-blocked") != "true"
    assert len(upstream.calls) == 1
