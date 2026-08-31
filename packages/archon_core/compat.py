"""Compatibility bridge to the proven AgentBeats defender modules.

The battle-tested defense logic (normalization, threat classification,
segmentation, execution modes, output guardrails, pyrit_defense) currently
lives in ``scenarios/security_arena/agents/defender/`` as pure-stdlib modules.
Those modules are loaded here by file path so archon_core can reuse them
without duplication and without breaking the competition harness.

This bridge is temporary: full physical extraction into this package is a
ROADMAP item (see ROADMAP.md / BLUEPRINT_HACKATHON.md §4 gap #1). The modules
loaded here are covered by the 286 existing unit tests plus the layer tests
in tests/armor/.
"""

from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

_FALLBACK_DIRNAME = Path("scenarios") / "security_arena" / "agents" / "defender"


def _candidate_dirs() -> list[Path]:
    """Locations searched for the AgentBeats defender modules, in order.

    1. ``$ARCHON_DEFENDER_DIR``            explicit override (containers/CI)
    2. ``<repo root>/scenarios/...``       development checkout layout
    3. ``<sys.prefix>/scenarios/...``      installed under a venv root
    4. ``<cwd>/scenarios/...``             container WORKDIR layout
    """
    cands: list[Path] = []
    env_dir = os.environ.get("ARCHON_DEFENDER_DIR")
    if env_dir:
        cands.append(Path(env_dir))
    cands.append(Path(__file__).resolve().parents[2] / _FALLBACK_DIRNAME)
    cands.append(Path(sys.prefix) / _FALLBACK_DIRNAME)
    cands.append(Path.cwd() / _FALLBACK_DIRNAME)
    return cands


_loaded: dict[str, object] = {}


def load_defender_module(name: str):
    """Load (and cache) a defender module by file path."""
    if name in _loaded:
        return _loaded[name]
    path = next(
        (cand / f"{name}.py" for cand in _candidate_dirs() if (cand / f"{name}.py").exists()),
        None,
    )
    if path is None:
        searched = ", ".join(str(c) for c in _candidate_dirs())
        raise ImportError(
            f"Defender module '{name}.py' not found. Searched: {searched}. "
            "Set ARCHON_DEFENDER_DIR to the directory containing the "
            "scenarios/security_arena/agents/defender modules."
        )
    qualname = f"archon_core._vendor.{name}"
    spec = importlib.util.spec_from_file_location(qualname, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[qualname] = module
    spec.loader.exec_module(module)
    _loaded[name] = module
    return module


normalization = load_defender_module("normalization")
threat_classifier = load_defender_module("threat_classifier")
segmenter = load_defender_module("segmenter")
execution_modes = load_defender_module("execution_modes")
output_guardrails = load_defender_module("output_guardrails")
pyrit_defense = load_defender_module("pyrit_defense")

__all__ = [
    "load_defender_module",
    "normalization",
    "threat_classifier",
    "segmenter",
    "execution_modes",
    "output_guardrails",
    "pyrit_defense",
]
