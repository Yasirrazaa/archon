"""Tool-call schema validation rail: fail-closed validation of tool invocations.

Blocks tool calls that reference unknown tools, miss required arguments,
carry wrongly-typed arguments, or add properties to strict schemas.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..models import Exchange
from .base import DefenseLayer

__all__ = ["ToolCallRail", "ToolSpec", "validate_tool_call"]


@dataclass
class ToolSpec:
    """Allowlisted tool with a JSON-schema-ish parameters schema."""

    name: str
    parameters_schema: dict[str, Any] = field(default_factory=dict)


def _type_matches(value: Any, expected: str) -> bool:
    if expected == "string":
        return isinstance(value, str)
    if expected == "boolean":
        return isinstance(value, bool)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected == "array":
        return isinstance(value, list)
    if expected == "object":
        return isinstance(value, dict)
    return True


def validate_tool_call(
    name: str, args: dict[str, Any], specs: list[ToolSpec]
) -> list[str]:
    """Return a list of schema findings for one tool call; empty means valid."""
    spec = next((s for s in specs if s.name == name), None)
    if spec is None:
        return [f"unknown tool '{name}'"]
    schema = spec.parameters_schema or {}
    if not isinstance(args, dict):
        return ["malformed arguments: expected object"]
    findings: list[str] = []
    for required in schema.get("required", []):
        if required not in args:
            findings.append(f"missing required argument '{required}'")
    properties = schema.get("properties", {})
    for arg_name, value in args.items():
        expected = properties.get(arg_name, {}).get("type")
        if expected and not _type_matches(value, expected):
            findings.append(
                f"argument '{arg_name}' must be of type '{expected}'"
            )
    if schema.get("additionalProperties") is False:
        for arg_name in args:
            if arg_name not in properties:
                findings.append(f"unexpected argument '{arg_name}'")
    return findings


class ToolCallRail(DefenseLayer):
    """Fail-closed schema validation for tool calls found on the exchange."""

    name = "tool_rail"

    def __init__(self, specs: list[ToolSpec]) -> None:
        self.specs = list(specs)

    async def process(self, exchange: Exchange) -> Exchange:
        calls = exchange.metadata.get("tool_calls")
        if calls is None:
            return exchange
        if not isinstance(calls, list):
            exchange.block("tool_rail: malformed tool call structure")
            return exchange
        for call in calls:
            if not isinstance(call, dict) or "name" not in call:
                exchange.block("tool_rail: malformed tool call structure")
                return exchange
            findings = validate_tool_call(call["name"], call.get("args"), self.specs)
            if findings:
                exchange.block(f"tool_rail: {findings[0]}")
                return exchange
        return exchange
