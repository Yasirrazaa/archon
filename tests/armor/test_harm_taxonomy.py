"""Tests for the harm-taxonomy YAML layer.

Harm definitions live in a versioned YAML artifact (inspired by PyRIT's
harm_definition datasets): every harm carries a human-readable name, an
OWASP/ASI mapping, and a 1-5 rubric scale so severity is *derived* from
attack success rate rather than hardcoded labels.
"""

from pathlib import Path

import yaml
from archon_core.reporting.harm_taxonomy import (
    HarmDefinition,
    classify_category,
    get_definition,
    load_harm_definitions,
    render_harm_table,
    severity_from_rate,
)

REQUIRED_IDS = {
    "privacy_exfiltration",
    "supply_chain",
    "behavior_change",
    "exploits_rce",
    "memory_poisoning",
    "inter_agent_trust",
    "cascading_failure",
    "trust_exploitation",
    "rogue_agent",
    "tool_misuse",
    "harmful_content",
    "misinformation",
}


class TestYamlData:
    def test_loads_at_least_ten_definitions(self):
        defs = load_harm_definitions()
        assert len(defs) >= 10

    def test_required_definitions_present(self):
        defs = {d.id for d in load_harm_definitions()}
        assert REQUIRED_IDS <= defs

    def test_every_definition_has_five_rubric_levels(self):
        for d in load_harm_definitions():
            assert set(d.scale.keys()) == {1, 2, 3, 4, 5}, d.id
            assert all(isinstance(v, str) and v.strip() for v in d.scale.values()), d.id

    def test_yaml_schema_fields(self):
        raw = yaml.safe_load(
            (Path(load_harm_definitions.__module__ and _data_path())).read_text()
        )
        assert isinstance(raw, list)
        for entry in raw:
            assert {"id", "name", "category", "description", "scale", "maps_to"} <= set(entry)

    def test_maps_to_covers_owasp_and_asi(self):
        defs = {d.id: d for d in load_harm_definitions()}
        assert set(defs["privacy_exfiltration"].maps_to) >= {"LLM02", "LLM07", "ASI06"}
        assert "ASI04" in defs["supply_chain"].maps_to
        assert "LLM01" in defs["harmful_content"].maps_to


class TestGetDefinition:
    def test_hit(self):
        d = get_definition("memory_poisoning")
        assert d is not None
        assert d.name

    def test_miss_returns_none(self):
        assert get_definition("nonexistent_harm") is None


class TestClassifyCategory:
    def test_data_exfiltration_maps_to_privacy(self):
        assert classify_category("data_exfiltration").id == "privacy_exfiltration"

    def test_supply_chain_aliases(self):
        assert classify_category("supply_chain").id == "supply_chain"
        assert classify_category("mcp").id == "supply_chain"

    def test_cascade_failure_maps_to_cascading_failure(self):
        assert classify_category("cascade_failure").id == "cascading_failure"

    def test_jailbreak_prefix_maps_to_harmful_content(self):
        assert classify_category("jailbreak").id == "harmful_content"
        assert classify_category("jailbreak_roleplay").id == "harmful_content"

    def test_unknown_returns_none(self):
        assert classify_category("totally_unknown_probe_category") is None


class TestSeverityBands:
    def test_rate_zero_is_level_1(self):
        assert severity_from_rate(0, 100, get_definition("tool_misuse")) == 1

    def test_band_boundaries(self):
        d = get_definition("tool_misuse")
        cases = [
            (24, 100, 2),   # 0.24 -> 2
            (25, 100, 3),   # 0.25 -> 3
            (49, 100, 3),   # 0.49 -> 3
            (50, 100, 4),   # 0.50 -> 4
            (74, 100, 4),   # 0.74 -> 4
            (75, 100, 5),   # 0.75 -> 5
            (100, 100, 5),  # 1.00 -> 5
        ]
        for blocked, total, expected in cases:
            assert severity_from_rate(blocked, total, d) == expected, (blocked, total)


class TestRenderTable:
    def test_table_has_header_rows_and_severities(self):
        coverage = {
            "data_exfiltration": {"blocked": 60, "total": 100},
            "supply_chain": {"blocked": 10, "total": 100},
        }
        defs = load_harm_definitions()
        table = render_harm_table(coverage, defs)
        lines = table.splitlines()
        assert "|" in table
        assert any("category" in ln.lower() for ln in lines[:2])
        assert any("privacy_exfiltration" in ln for ln in lines)
        assert any("supply_chain" in ln for ln in lines)
        assert any("4" in ln and "privacy_exfiltration" in ln for ln in lines)
        assert any("2" in ln and "supply_chain" in ln for ln in lines)

    def test_unknown_category_row_is_skipped(self):
        table = render_harm_table({"bogus": {"blocked": 1, "total": 1}}, load_harm_definitions())
        assert "bogus" not in table


def _data_path() -> str:
    from archon_core.reporting import harm_taxonomy

    return str(Path(harm_taxonomy.__file__).parent / "data" / "harm_definitions.yaml")


class TestDataclass:
    def test_roundtrip_fields(self):
        d = get_definition("rogue_agent")
        assert isinstance(d, HarmDefinition)
        assert d.id == "rogue_agent"
        assert isinstance(d.category, str)
        assert isinstance(d.description, str)
        assert all(isinstance(k, int) for k in d.scale)
