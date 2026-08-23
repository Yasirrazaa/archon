"""TDD Phase 2: Registry MVP — agent cards, security policies, backends."""

import pytest
from archon_core.registry.base import (
    AgentCard,
    AgentNotFoundError,
    DuplicateAgentError,
    Registry,
    SecurityPolicy,
)
from archon_core.registry.memory import InMemoryRegistry
from archon_core.registry.sqlite import SqliteRegistry


def make_card(agent_id="agent-1", **overrides) -> AgentCard:
    defaults = dict(
        agent_id=agent_id,
        name="Support Agent",
        version="1.0.0",
        capabilities=["chat", "tool_use"],
        policy=SecurityPolicy(upstream_base_url="https://api.upstream.test/v1"),
    )
    defaults.update(overrides)
    return AgentCard(**defaults)


@pytest.fixture(params=[InMemoryRegistry, lambda: SqliteRegistry(":memory:")])
def registry(request) -> Registry:
    return request.param()


def test_register_and_get_roundtrip(registry):
    card = make_card()
    registry.register(card)
    fetched = registry.get("agent-1")
    assert fetched == card


def test_register_duplicate_rejected(registry):
    registry.register(make_card())
    with pytest.raises(DuplicateAgentError):
        registry.register(make_card())


def test_get_missing_agent_raises(registry):
    with pytest.raises(AgentNotFoundError):
        registry.get("nope")


def test_get_policy_returns_agent_policy(registry):
    policy = SecurityPolicy(min_confidence=0.9, max_llm_budget=2)
    registry.register(make_card(policy=policy))
    assert registry.get_policy("agent-1") == policy


def test_delete_agent(registry):
    registry.register(make_card())
    assert registry.delete("agent-1") is True
    with pytest.raises(AgentNotFoundError):
        registry.get("agent-1")
    assert registry.delete("agent-1") is False


def test_list_agents(registry):
    registry.register(make_card("a"))
    registry.register(make_card("b"))
    ids = {c.agent_id for c in registry.list_agents()}
    assert ids == {"a", "b"}


def test_sqlite_registry_persists_across_instances(tmp_path):
    db = str(tmp_path / "registry.db")
    reg1 = SqliteRegistry(db)
    reg1.register(make_card("persist-me"))

    reg2 = SqliteRegistry(db)
    assert reg2.get("persist-me").policy.upstream_base_url == "https://api.upstream.test/v1"


def test_policy_defaults_are_safe():
    policy = SecurityPolicy()
    assert policy.max_llm_budget > 0
    assert "indirect_injection" in policy.block_categories
