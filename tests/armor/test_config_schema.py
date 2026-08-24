"""Sprint W7-I — JSON-schema validation for archon.yaml (promptfoo-grade DX).

The shipped example config must always validate CLEAN against
schemas/archon-config.schema.json, and the stdlib-only mini-validator must
report precise, human-readable errors for real config mistakes.
"""

from __future__ import annotations

import json

import yaml
from archon_armor.config_schema import (
    SCHEMA_PATH,
    load_config,
    validate_config,
    validate_config_file,
)

REPO_ROOT = SCHEMA_PATH.parents[1]
EXAMPLE = REPO_ROOT / "examples" / "archon.yaml"


def _load_schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def test_schema_path_exists():
    assert SCHEMA_PATH.is_file()


def test_schema_is_valid_json_with_meta_fields():
    schema = _load_schema()
    assert "$schema" in schema
    assert schema.get("type") == "object"
    assert isinstance(schema.get("properties"), dict)


def test_shipped_example_config_validates_clean():
    data = load_config(str(EXAMPLE))
    errors = validate_config(data)
    assert errors == []


def test_empty_dict_valid_per_schema():
    # Every key is optional (loader applies defaults), so {} is valid.
    assert validate_config({}) == []


def test_missing_required_key_reported():
    schema = {"type": "object", "required": ["target"], "properties": {"target": {}}}
    errors = validate_config({"model": "default"}, schema)
    assert len(errors) == 1
    assert "target" in errors[0]
    assert "required" in errors[0]


def test_wrong_type_reported_with_path():
    schema = _load_schema()
    errors = validate_config({"ci": "yes-please"}, schema)
    assert any("ci" in e and "object" in e for e in errors)


def test_unknown_top_level_key_reported():
    schema = _load_schema()
    errors = validate_config({"targets": "http://x", "target": "http://y"}, schema)
    assert any("targets" in e for e in errors)
    assert not any("unknown key" in e and '"target"' in e for e in errors)


def test_enum_violation_reported():
    schema = _load_schema()
    errors = validate_config({"pack": "ultra_pro_max"}, schema)
    assert any("pack" in e and "enum" in e.lower() or "one of" in e for e in errors)


def test_enum_accepted_values_pass():
    schema = _load_schema()
    assert validate_config({"pack": "core"}, schema) == []
    assert validate_config({"pack": "owasp_llm_10"}, schema) == []


def test_nested_error_paths_correct():
    schema = {
        "type": "object",
        "properties": {
            "policies": {
                "type": "object",
                "properties": {"block_categories": {"type": "array"}},
            }
        },
    }
    errors = validate_config(
        {"policies": {"block_categories": "not-an-array"}}, schema
    )
    assert errors == ["policies.block_categories: expected array, got str"]


def test_minimum_violation_reported():
    schema = _load_schema()
    errors = validate_config({"ci": {"enabled": True, "min_block_rate": -0.1}}, schema)
    assert any("min_block_rate" in e and "minimum" in e.lower() for e in errors)


def test_maximum_violation_reported():
    schema = _load_schema()
    errors = validate_config({"ci": {"min_block_rate": 1.5}}, schema)
    assert any("max_block" in e or "maximum" in e.lower() for e in errors)


def test_boundary_min_block_rate_values_accept():
    schema = _load_schema()
    assert validate_config({"ci": {"min_block_rate": 0}}, schema) == []
    assert validate_config({"ci": {"min_block_rate": 1}}, schema) == []
    assert validate_config({"ci": {"min_block_rate": 0.9}}, schema) == []


def test_boolean_is_not_integer():
    schema = {"type": "object", "properties": {"n": {"type": "integer"}}}
    errors = validate_config({"n": True}, schema)
    assert errors == ["n: expected integer, got bool"]


def test_integer_counts_as_number():
    schema = {"type": "object", "properties": {"rate": {"type": "number"}}}
    assert validate_config({"rate": 1}, schema) == []


def test_non_object_root_reported():
    schema = _load_schema()
    errors = validate_config(["not", "a", "dict"], schema)
    assert errors
    assert "object" in errors[0]


def test_validate_config_file_good_yaml(tmp_path):
    p = tmp_path / "good.yaml"
    p.write_text("target: http://gw:8080\npack: core\n")
    assert validate_config_file(str(p)) == []


def test_validate_config_file_bad_yaml(tmp_path):
    p = tmp_path / "bad.yaml"
    p.write_text("target: http://gw:8080\njson_output: sometimes\n")
    errors = validate_config_file(str(p))
    assert errors
    assert any("json_output" in e for e in errors)


def test_error_messages_contain_offending_key():
    schema = _load_schema()
    errors = validate_config({"model": ["gpt", "claude"]}, schema)
    assert any("model" in e for e in errors)


def test_load_config_returns_dict_from_yaml(tmp_path):
    p = tmp_path / "c.yaml"
    p.write_text(yaml.safe_dump({"target": "http://x", "ci": {"enabled": False}}))
    data = load_config(str(p))
    assert data == {"target": "http://x", "ci": {"enabled": False}}


def test_default_schema_used_when_none_passed():
    # validate_config(None schema) loads SCHEMA_PATH internally.
    errors = validate_config({"totally_unknown": 1})
    assert any("totally_unknown" in e for e in errors)
