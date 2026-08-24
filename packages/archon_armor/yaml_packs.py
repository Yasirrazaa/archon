"""Nuclei-style YAML declarative probe packs.

Community members contribute probe packs WITHOUT writing Python: drop a
``*.yaml`` file into a directory, call :func:`register_yaml_packs`, done.

Schema (all keys required unless noted)::

    name: example_yaml_pack          # unique pack name (registry key)
    category: contrib_yaml_example   # must start with 'contrib_'
    description: One-line summary.   # optional but recommended
    probes:
      - name: exy_probe_one          # unique within the pack
        payload: "Attack text..."    # >= 10 chars

Invalid structure raises :class:`ValueError` with the file path and probe
name included so authors can fix their pack without reading source.
"""

from __future__ import annotations

from pathlib import Path

import yaml

from archon_armor.probes import PROBE_PACKS, Probe

MIN_PAYLOAD_CHARS = 10
REQUIRED_CONTRIB_PREFIX = "contrib_"
_YAML_SUFFIXES = (".yaml", ".yml")


def _fail(path: Path | str, reason: str) -> ValueError:
    return ValueError(f"{path}: {reason}")


def load_yaml_pack(path: str) -> list[Probe]:
    """Parse and validate one YAML pack file. Returns its probes."""
    p = Path(path)
    if not p.is_file():
        raise ValueError(f"{path}: pack file does not exist")

    try:
        return _parse_pack(p)[1]
    except yaml.YAMLError as exc:
        raise ValueError(f"{path}: invalid YAML ({exc})") from exc


def load_yaml_dir(dir_path: str) -> dict[str, list[Probe]]:
    """Load every ``*.yaml``/``*.yml`` pack in ``dir_path``, keyed by pack name."""
    d = Path(dir_path)
    if not d.is_dir():
        raise ValueError(f"{dir_path}: pack directory does not exist")

    packs: dict[str, list[Probe]] = {}
    for p in sorted(d.iterdir()):
        if not p.is_file() or p.suffix.lower() not in _YAML_SUFFIXES:
            continue
        pack_name, probes = _parse_pack(p)
        if pack_name in packs:
            raise ValueError(
                f"{dir_path}: duplicate pack name '{pack_name}' "
                f"(also defined by another file)"
            )
        packs[pack_name] = probes
    return packs


def register_yaml_packs(dir_path: str) -> list[str]:
    """Merge every YAML pack in ``dir_path`` into PROBE_PACKS.

    Idempotent per pack name: re-registering an existing name replaces the
    previous pack in place. Returns the sorted list of registered names.
    """
    loaded = load_yaml_dir(dir_path)
    for name, probes in loaded.items():
        PROBE_PACKS[name] = probes
    return sorted(loaded)


def _parse_pack(p: Path) -> tuple[str, list[Probe]]:
    """Validate one YAML file; return ``(pack_name, probes)``."""
    data = yaml.safe_load(p.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise _fail(p, "top-level structure must be a mapping of pack metadata")

    pack_name = data.get("name")
    if not isinstance(pack_name, str) or not pack_name.strip():
        raise _fail(p, "missing or empty required key 'name'")

    category = data.get("category")
    if not isinstance(category, str) or not category.strip():
        raise _fail(p, "missing or empty required key 'category'")
    if not category.startswith(REQUIRED_CONTRIB_PREFIX):
        raise _fail(
            p,
            f"category '{category}' must start with '{REQUIRED_CONTRIB_PREFIX}'",
        )

    entries = data.get("probes")
    if not isinstance(entries, list) or not entries:
        raise _fail(p, "missing or empty required key 'probes' (non-empty list)")

    probes: list[Probe] = []
    seen: set[str] = set()
    for i, entry in enumerate(entries):
        where = f"probe #{i + 1}"
        if not isinstance(entry, dict):
            raise _fail(p, f"{where}: each probe entry must be a mapping")
        probe_name = entry.get("name")
        payload = entry.get("payload")
        if not isinstance(probe_name, str) or not probe_name.strip():
            raise _fail(p, f"{where}: missing or empty required key 'name'")
        if probe_name in seen:
            raise _fail(p, f"duplicate probe name '{probe_name}'")
        seen.add(probe_name)
        if not isinstance(payload, str) or len(payload.strip()) < MIN_PAYLOAD_CHARS:
            raise _fail(
                p,
                f"probe '{probe_name}': payload must be a string of at least "
                f"{MIN_PAYLOAD_CHARS} non-whitespace characters",
            )
        probes.append(Probe(name=probe_name, payload=payload, category=category))
    return pack_name, probes
