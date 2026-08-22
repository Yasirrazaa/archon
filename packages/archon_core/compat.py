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
import sys
from pathlib import Path

_DEFENDER_DIR = (
    Path(__file__).resolve().parents[2] / "scenarios" / "security_arena" / "agents" / "defender"
)

_loaded: dict[str, object] = {}


def load_defender_module(name: str):
    """Load (and cache) a defender module by file path."""
    if name in _loaded:
        return _loaded[name]
    path = _DEFENDER_DIR / f"{name}.py"
    if not path.exists():
        raise ImportError(f"Defender module not found: {path}")
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
