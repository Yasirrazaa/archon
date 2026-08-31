"""Regression: compat defender-module resolution must work when the package
is *installed* (site-packages), not just from a repo checkout — this broke
the first Cloud Run/Cloud Shell container run (ImportError on normalization).
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from archon_core import compat


class TestDefenderModuleResolution:
    def test_repo_checkout_layout_still_works(self):
        # In a checkout, parents[2] is the repo root; the canonical import
        # at module import time already proves this path.
        assert compat.normalization is not None
        assert compat.threat_classifier is not None

    def test_cwd_candidate_resolves_container_layout(self, tmp_path: Path, monkeypatch):
        # Simulate the container: WORKDIR contains a defender module that the
        # repo checkout does NOT have, so only the cwd candidate can find it.
        ddir = tmp_path / "scenarios" / "security_arena" / "agents" / "defender"
        ddir.mkdir(parents=True)
        (ddir / "zz_container_probe.py").write_text("VALUE = 'container'\n", encoding="utf-8")
        monkeypatch.chdir(tmp_path)
        monkeypatch.setattr(compat, "_loaded", {})

        mod = compat.load_defender_module("zz_container_probe")
        assert mod.VALUE == "container"  # type: ignore[attr-defined]
        compat._loaded.clear()

    def test_env_override_wins(self, tmp_path: Path, monkeypatch):
        ddir = tmp_path / "defenders"
        ddir.mkdir()
        (ddir / "segmenter.py").write_text("VALUE = 'override'\n", encoding="utf-8")
        monkeypatch.setenv("ARCHON_DEFENDER_DIR", str(ddir))
        monkeypatch.setattr(compat, "_loaded", {})

        mod = compat.load_defender_module("segmenter")
        assert mod.VALUE == "override"  # type: ignore[attr-defined]
        compat._loaded.clear()

    def test_missing_everywhere_raises_actionable_error(self, tmp_path: Path, monkeypatch):
        monkeypatch.setattr(compat, "_loaded", {})
        monkeypatch.delenv("ARCHON_DEFENDER_DIR", raising=False)
        # Simulate a hostile install: no candidate location has the module.
        empty = tmp_path / "empty"
        empty.mkdir()
        monkeypatch.setattr(
            compat, "_candidate_dirs", lambda: [empty, empty, empty], raising=False
        )
        with pytest.raises(ImportError, match="ARCHON_DEFENDER_DIR"):
            compat.load_defender_module("no_such_module_xyz")
        compat._loaded.clear()
