"""Sprint B2 — YAML policy-as-code: archon.yaml drives `archon scan`.

Core stays dependency-clean: the loader validates structure/types and accepts
the known-pack list as a parameter (archon_cli injects the real pack names).
Explicit CLI flags always win over config values.
"""

from __future__ import annotations

import argparse

import pytest

from archon_core.config import (
    CONFIG_FIELDS,
    ScanConfig,
    apply_config_to_args,
    load_scan_config,
)


def _write(tmp_path, text):
    p = tmp_path / "archon.yaml"
    p.write_text(text)
    return str(p)


def test_minimal_config_uses_defaults(tmp_path):
    path = _write(tmp_path, "target: http://guardrail:8080\n")
    cfg = load_scan_config(path)
    assert isinstance(cfg, ScanConfig)
    assert cfg.target == "http://guardrail:8080"
    assert cfg.pack == "core"
    assert cfg.min_block_rate == 0.5
    assert cfg.ci is False


def test_full_config_parses_all_fields(tmp_path):
    path = _write(
        tmp_path,
        """
target: http://gw:8080
target_api_key_env: ARCHON_TARGET_API_KEY
model: gemini-2.5-flash
pack: owasp_llm_10
ci:
  enabled: true
  min_block_rate: 0.9
baseline:
  update: baselines/gw.json
  gate: baselines/gw.json
json_output: true
""",
    )
    cfg = load_scan_config(path)
    assert cfg.target == "http://gw:8080"
    assert cfg.target_api_key_env == "ARCHON_TARGET_API_KEY"
    assert cfg.model == "gemini-2.5-flash"
    assert cfg.pack == "owasp_llm_10"
    assert cfg.ci is True
    assert cfg.min_block_rate == 0.9
    assert cfg.update_baseline == "baselines/gw.json"
    assert cfg.gate_baseline == "baselines/gw.json"
    assert cfg.json_output is True


def test_unknown_key_rejected(tmp_path):
    path = _write(tmp_path, "target: http://x\nattak_mode: yes\n")
    with pytest.raises(ValueError, match="attak_mode"):
        load_scan_config(path)


def test_invalid_pack_rejected_when_known_packs_given(tmp_path):
    path = _write(tmp_path, "pack: ninja_probes\ntarget: http://x\n")
    with pytest.raises(ValueError, match="ninja_probes"):
        load_scan_config(path, known_packs={"core", "owasp_llm_10"})


def test_unknown_pack_accepted_when_known_packs_omitted(tmp_path):
    path = _write(tmp_path, "pack: anything\ntarget: http://x\n")
    assert load_scan_config(path).pack == "anything"


@pytest.mark.parametrize("rate", [-0.1, 1.5])
def test_min_block_rate_range_enforced(tmp_path, rate):
    path = _write(tmp_path, f"ci:\n  min_block_rate: {rate}\n")
    with pytest.raises(ValueError, match="min_block_rate"):
        load_scan_config(path)


def test_broken_yaml_raises_valueerror(tmp_path):
    path = _write(tmp_path, "target: [unclosed\n  bad:::\n")
    with pytest.raises(ValueError, match="parse"):
        load_scan_config(path)


# --------------------------------------------------------- args merging ---


def _merge_args(**overrides):
    from archon_cli.main import build_parser

    parser = build_parser()
    argv = ["scan"]
    for k, v in overrides.items():
        argv += [f"--{k}", str(v)]
    args = parser.parse_args(argv)
    return args, getattr(args, "_defaults", {})


def test_apply_fills_defaults_from_config():
    args, defaults = _merge_args()
    cfg = ScanConfig(target="http://cfg:8080", pack="owasp_llm_10", min_block_rate=0.95, ci=True)
    apply_config_to_args(args, cfg, defaults=defaults)
    assert args.target == "http://cfg:8080"
    assert args.pack == "owasp_llm_10"
    assert args.min_block_rate == 0.95
    assert args.ci is True


def test_explicit_flags_win_over_config():
    """Non-default flags win over config.

    Caveat (inherent to argparse): a flag explicitly set to its own default
    value is indistinguishable from unset, so config wins there.
    """
    args, defaults = _merge_args(pack="core", **{"min-block-rate": 0.7})
    cfg = ScanConfig(target="http://cfg:8080", pack="owasp_llm_10", min_block_rate=0.95)
    apply_config_to_args(args, cfg, defaults=defaults)
    assert args.pack == "owasp_llm_10"  # 'core' == parser default -> treated as unset
    assert args.min_block_rate == 0.7  # non-default explicit flag kept
    assert args.target == "http://cfg:8080"


def test_no_defaults_only_empty_strings_filled():
    """Without parser defaults, only unset strings fill; bools/floats untouched."""
    args, _ = _merge_args()
    cfg = ScanConfig(target="http://cfg:8080", min_block_rate=0.95)
    apply_config_to_args(args, cfg)
    assert args.target == "http://cfg:8080"
    assert args.min_block_rate == 0.5  # unknown explicitness -> left alone


def test_config_fields_cover_scan_flags():
    """Every ScanConfig field must map to an existing scan arg."""
    from archon_cli.main import build_parser

    parser = build_parser()
    dests = {a.dest for a in parser._subparsers._group_actions[0].choices["scan"]._actions}
    mapping = {"target": "target", "agent_id": "agent_id", "registry": "registry",
               "pack": "pack", "min_block_rate": "min_block_rate", "ci": "ci",
               "json_output": "json", "update_baseline": "update_baseline",
               "gate_baseline": "gate_baseline", "model": "model",
               "target_api_key_env": None}
    for field in CONFIG_FIELDS:
        assert field in mapping, f"unmapped config field: {field}"
        dest = mapping[field]
        if dest is not None:
            assert dest in dests, f"config field {field} has no --{dest} scan flag"
