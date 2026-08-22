"""YAML policy-as-code configuration for `archon scan`.

archon.yaml makes security scans versioned, reviewable artifacts:

    target: http://guardrail:8080
    pack: owasp_llm_10
    ci:
      enabled: true
      min_block_rate: 0.9

Core stays dependency-clean: pack-name validation is injected via
`known_packs`, and YAML parsing requires only PyYAML (already a transitive
dependency). Explicit CLI flags always win over config values.
"""

from __future__ import annotations

from dataclasses import dataclass

import yaml


@dataclass
class ScanConfig:
    target: str = ""
    registry: str = ""
    agent_id: str = ""
    pack: str = "core"
    model: str = "default"
    target_api_key_env: str = ""
    ci: bool = False
    min_block_rate: float = 0.5
    json_output: bool = False
    update_baseline: str = ""
    gate_baseline: str = ""


CONFIG_FIELDS = frozenset(ScanConfig.__dataclass_fields__)

# config field -> argparse dest on the `scan` subcommand (None = no flag)
_ARG_DEST = {
    "target": "target",
    "registry": "registry",
    "agent_id": "agent_id",
    "pack": "pack",
    "model": "model",
    "target_api_key_env": None,  # resolved via env at scan time
    "ci": "ci",
    "min_block_rate": "min_block_rate",
    "json_output": "json",
    "update_baseline": "update_baseline",
    "gate_baseline": "gate_baseline",
}


def load_scan_config(path: str, known_packs: set[str] | None = None) -> ScanConfig:
    try:
        with open(path, encoding="utf-8") as fh:
            raw = yaml.safe_load(fh) or {}
    except yaml.YAMLError as exc:
        raise ValueError(f"failed to parse {path}: {exc}") from exc
    if not isinstance(raw, dict):
        raise ValueError(f"{path}: top-level document must be a mapping")

    unknown = set(raw) - CONFIG_FIELDS - {"ci", "baseline"}
    if unknown:
        raise ValueError(f"unknown config key(s): {', '.join(sorted(unknown))}")

    ci = raw.get("ci") or {}
    if not isinstance(ci, dict):
        raise ValueError("'ci' must be a mapping with enabled/min_block_rate")
    baseline = raw.get("baseline") or {}
    if not isinstance(baseline, dict):
        raise ValueError("'baseline' must be a mapping with update/gate")

    rate = ci.get("min_block_rate", 0.5)
    if not isinstance(rate, (int, float)) or not (0.0 <= rate <= 1.0):
        raise ValueError("ci.min_block_rate must be a number between 0 and 1")

    pack = str(raw.get("pack", "core"))
    if known_packs is not None and pack not in known_packs:
        raise ValueError(
            f"unknown pack {pack!r}; available packs: {', '.join(sorted(known_packs))}"
        )

    return ScanConfig(
        target=str(raw.get("target", "")),
        registry=str(raw.get("registry", "")),
        agent_id=str(raw.get("agent_id", "")),
        pack=pack,
        model=str(raw.get("model", "default")),
        target_api_key_env=str(raw.get("target_api_key_env", "")),
        ci=bool(ci.get("enabled", False)),
        min_block_rate=float(rate),
        json_output=bool(raw.get("json_output", False)),
        update_baseline=str(baseline.get("update", "")),
        gate_baseline=str(baseline.get("gate", "")),
    )


def apply_config_to_args(args: argparse.Namespace, cfg: ScanConfig,
                         defaults: dict[str, object] | None = None) -> None:
    """Fill unset scan args from cfg; explicit flags win.

    `defaults` maps dest -> parser default; when omitted, values are applied
    only for falsy/None args except numeric ones handled by caller-provided
    defaults.
    """
    for field, dest in _ARG_DEST.items():
        if dest is None:
            continue
        cfg_value = getattr(cfg, field)
        current = getattr(args, dest)
        untouched = (
            current == defaults[dest]
            if defaults is not None and dest in defaults
            else (current is None or current == "" or dest == "ci" and current is False)
        )
        if untouched and cfg_value not in ("", None):
            setattr(args, dest, cfg_value)


__all__ = [
    "CONFIG_FIELDS",
    "ScanConfig",
    "apply_config_to_args",
    "load_scan_config",
]
