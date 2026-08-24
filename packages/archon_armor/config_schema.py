"""Stdlib-only JSON-schema (subset) validation for archon.yaml.

Sprint W7-I — competitor gap closure: promptfoo-grade DX for YAML configs.
Implements exactly the schema subset used by schemas/archon-config.schema.json:
type, properties recursion, required, enum, additionalProperties:false,
minimum/maximum. Returns human-readable error strings; [] means valid.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import yaml

SCHEMA_PATH = Path(__file__).parents[2] / "schemas" / "archon-config.schema.json"

_TYPE_NAMES: dict[type, str] = {
    type(None): "null",
    bool: "bool",
    int: "int",
    float: "float",
    str: "str",
    list: "list",
    dict: "dict",
}


def load_config(path: str) -> dict[str, Any]:
    """Load a YAML config file as a mapping."""
    with open(path, encoding="utf-8") as fh:
        data = yaml.safe_load(fh)
    if not isinstance(data, dict):
        raise ValueError(f"{path}: top-level document must be a mapping")
    return data


def _check_type(value: Any, expected: str) -> bool:
    if expected == "object":
        return isinstance(value, dict)
    if expected == "array":
        return isinstance(value, list)
    if expected == "string":
        return isinstance(value, str)
    if expected == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if expected == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if expected == "boolean":
        return isinstance(value, bool)
    return True  # unknown type keyword: don't fail


def _type_name(value: Any) -> str:
    for py_type, name in _TYPE_NAMES.items():
        if py_type is type(value) and not (
            py_type in (int, float) and isinstance(value, bool)
        ):
            return name
    return type(value).__name__


def _validate_node(value: Any, node: dict[str, Any], path: str,
                   errors: list[str]) -> None:
    expected_type = node.get("type")
    if expected_type is not None and not _check_type(value, expected_type):
        errors.append(f"{path or '<root>'}: expected {expected_type}, "
                      f"got {_type_name(value)}")
        return

    if "enum" in node and value not in node["enum"]:
        allowed = ", ".join(repr(v) for v in node["enum"])
        errors.append(f"{path}: must be one of [{allowed}], got {value!r}")

    if "minimum" in node and isinstance(value, (int, float)) \
            and not isinstance(value, bool) and value < node["minimum"]:
        errors.append(f"{path}: minimum is {node['minimum']}, got {value}")

    if "maximum" in node and isinstance(value, (int, float)) \
            and not isinstance(value, bool) and value > node["maximum"]:
        errors.append(f"{path}: maximum is {node['maximum']}, got {value}")

    if isinstance(value, dict):
        props = node.get("properties", {})
        for key in node.get("required", []):
            if key not in value:
                errors.append(f"{path + '.' if path else ''}{key}: required key "
                              f"is missing")
        if node.get("additionalProperties") is False:
            for key in sorted(set(value) - set(props)):
                errors.append(f"{path + '.' if path else ''}{key}: unknown key "
                              f"(additionalProperties: false)")
        for key, sub_value in value.items():
            if key in props:
                sub_path = f"{path}.{key}" if path else key
                _validate_node(sub_value, props[key], sub_path, errors)


def validate_config(data: Any, schema: dict[str, Any] | None = None) -> list[str]:
    """Validate config data against the shipped (or given) schema.

    Returns a list of human-readable error strings; an empty list is valid.
    """
    if schema is None:
        schema = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
    errors: list[str] = []
    _validate_node(data, schema, "", errors)
    return errors


def validate_config_file(path: str) -> list[str]:
    """Load a YAML config file and validate it against the shipped schema."""
    return validate_config(load_config(path))


__all__ = ["SCHEMA_PATH", "load_config", "validate_config", "validate_config_file"]
