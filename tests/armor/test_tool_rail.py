"""TDD: tool-call schema validation rail tests."""

import pytest
from archon_core.defenses.base import DefensePipeline
from archon_core.defenses.tool_rail import ToolCallRail, ToolSpec, validate_tool_call
from archon_core.models import Exchange

SPECS = [
    ToolSpec(
        name="search",
        parameters_schema={
            "type": "object",
            "properties": {
                "query": {"type": "string"},
                "limit": {"type": "integer"},
                "verbose": {"type": "boolean"},
                "ratio": {"type": "number"},
                "tags": {"type": "array"},
                "filters": {"type": "object"},
            },
            "required": ["query"],
        },
    ),
    ToolSpec(
        name="open_schema",
        parameters_schema={
            "type": "object",
            "properties": {"a": {"type": "string"}},
        },
    ),
]


def call(name, args):
    return Exchange(content="x", metadata={"tool_calls": [{"name": name, "args": args}]})


def test_valid_call_passes():
    assert validate_tool_call("search", {"query": "hello"}, SPECS) == []


def test_unknown_tool_blocked():
    findings = validate_tool_call("nope", {}, SPECS)
    assert len(findings) == 1


def test_missing_required_blocked():
    findings = validate_tool_call("search", {}, SPECS)
    assert any("query" in f for f in findings)


@pytest.mark.parametrize("expected_type", [
    ("string"),
    ("integer"),
    ("number"),
    ("boolean"),
    ("array"),
    ("object"),
])
def test_wrong_primitive_types_blocked(expected_type):
    wrong_value = {
        "string": ("query", 42),
        "integer": ("limit", "many"),
        "number": ("ratio", "lots"),
        "boolean": ("verbose", "yes"),
        "array": ("tags", "not-a-list"),
        "object": ("filters", ["not", "a", "dict"]),
    }[expected_type]
    findings = validate_tool_call("search", dict([wrong_value]), SPECS)
    assert any(expected_type in f for f in findings)


def test_extra_property_blocked_with_additional_properties_false():
    spec = ToolSpec(
        name="strict",
        parameters_schema={
            "type": "object",
            "properties": {"a": {"type": "string"}},
            "additionalProperties": False,
        },
    )
    findings = validate_tool_call("strict", {"a": "ok", "evil": True}, [spec])
    assert any("evil" in f for f in findings)


def test_extra_property_allowed_when_not_specified():
    findings = validate_tool_call("open_schema", {"a": "x", "extra": 1}, SPECS)
    assert findings == []


def test_malformed_args_fail_closed():
    findings = validate_tool_call("search", "not a dict", SPECS)
    assert len(findings) == 1


@pytest.mark.asyncio
async def test_no_tool_call_exchange_passthrough():
    rail = ToolCallRail(specs=SPECS)
    ex = await rail.process(Exchange(content="just text"))
    assert not ex.blocked
    assert ex.content == "just text"


@pytest.mark.asyncio
async def test_rail_name_is_tool_rail():
    assert ToolCallRail(specs=SPECS).name == "tool_rail"


@pytest.mark.asyncio
async def test_rail_blocks_violating_call():
    rail = ToolCallRail(specs=SPECS)
    ex = await rail.process(call("nope", {}))
    assert ex.blocked
    assert ex.block_reason.startswith("tool_rail: ")


@pytest.mark.asyncio
async def test_rail_blocks_wrong_type():
    rail = ToolCallRail(specs=SPECS)
    ex = await rail.process(call("search", {"query": "q", "limit": "many"}))
    assert ex.blocked
    assert "tool_rail:" in ex.block_reason


@pytest.mark.asyncio
async def test_pipeline_blocks_violating_exchange():
    pipeline = DefensePipeline([ToolCallRail(specs=SPECS)])
    ex = await pipeline.run(call("missing_tool", {}))
    assert ex.blocked


@pytest.mark.asyncio
async def test_pipeline_passes_clean_exchange():
    pipeline = DefensePipeline([ToolCallRail(specs=SPECS)])
    ex = await pipeline.run(call("search", {"query": "weather"}))
    assert not ex.blocked
