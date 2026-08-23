"""Contrib probe-pack gallery: every shipped community pack must load cleanly.

The gallery lives in ``contrib/`` at the repo root. Each ``*.py`` file defines
a module-level ``PROBES`` list of archon_armor.probes.Probe entries and is
loaded at runtime via ARCHON_CONTRIB_DIR (see archon_cli._contrib_packs).
"""

from __future__ import annotations

import os

import pytest

from archon_armor.probes import Probe, load_pack_file

CONTRIB_DIR = os.path.join(
    os.path.dirname(__file__), "..", "..", "contrib"
)


@pytest.fixture()
def _restore_packs():
    """Snapshot PROBE_PACKS so gallery loads never leak between tests."""
    from archon_armor.probes import PROBE_PACKS

    snapshot = dict(PROBE_PACKS)
    yield
    PROBE_PACKS.clear()
    PROBE_PACKS.update(snapshot)


def _pack_files() -> list[str]:
    if not os.path.isdir(CONTRIB_DIR):
        return []
    return sorted(
        f for f in os.listdir(CONTRIB_DIR) if f.endswith(".py") and not f.startswith("_")
    )


class TestGalleryContents:
    def test_gallery_ships_at_least_three_packs(self):
        files = _pack_files()
        assert len(files) >= 3, f"expected >=3 contrib packs, found {files}"

    @pytest.mark.parametrize("filename", _pack_files(), ids=lambda f: f[:-3])
    def test_every_pack_loads_via_load_pack_file(self, filename, _restore_packs):
        pack_name = load_pack_file(os.path.join(CONTRIB_DIR, filename))
        assert pack_name == filename[:-3]

    @pytest.mark.parametrize("filename", _pack_files(), ids=lambda f: f[:-3])
    def test_pack_shape_and_breadth(self, filename, _restore_packs):
        from archon_armor.probes import get_pack

        name = load_pack_file(os.path.join(CONTRIB_DIR, filename))
        probes = get_pack(name)
        assert len(probes) >= 5, f"{name}: expected >=5 probes"
        names = [p.name for p in probes]
        assert len(names) == len(set(names)), f"{name}: duplicate probe names"
        for p in probes:
            assert isinstance(p, Probe)
            assert p.category.startswith("contrib_"), p.category
            assert len(p.payload) > 20, f"{p.name}: payload too trivial"

    @pytest.mark.parametrize("filename", _pack_files(), ids=lambda f: f[:-3])
    def test_probe_names_namespaced_by_pack(self, filename, _restore_packs):
        from archon_armor.probes import get_pack

        name = load_pack_file(os.path.join(CONTRIB_DIR, filename))
        tokens = {p.name.split("_")[0] for p in get_pack(name)}
        assert len(tokens) == 1, (
            f"{name}: probe names must share one namespace token, got {sorted(tokens)}"
        )


class TestGalleryIndex:
    def test_readme_indexes_every_pack(self):
        readme = os.path.join(CONTRIB_DIR, "README.md")
        assert os.path.isfile(readme), "contrib/README.md missing"
        text = open(readme, encoding="utf-8").read()
        for f in _pack_files():
            assert f in text, f"contrib/README.md does not mention {f}"


class TestCliIntegration:
    def test_contrib_dir_env_loads_all_packs(self, _restore_packs, monkeypatch):
        from archon_cli.main import _contrib_packs

        monkeypatch.setenv("ARCHON_CONTRIB_DIR", os.path.abspath(CONTRIB_DIR))
        loaded = _contrib_packs()
        assert len(loaded) >= 3
        # Loaded packs are immediately usable by scans.
        from archon_armor.probes import get_pack

        assert all(len(get_pack(n)) >= 5 for n in loaded)

    def test_scan_runs_loaded_contrib_pack(self, _restore_packs, monkeypatch, tmp_path):
        """End-to-end: a contrib pack flows through BattleManager like any core pack."""
        from archon_armor.battles import BattleManager
        from archon_armor.probes import get_pack
        from archon_cli.main import _contrib_packs
        from archon_core.registry.base import AgentCard, SecurityPolicy
        from archon_core.registry.memory import InMemoryRegistry

        monkeypatch.setenv("ARCHON_CONTRIB_DIR", os.path.abspath(CONTRIB_DIR))
        loaded = _contrib_packs()
        registry = InMemoryRegistry()
        card = AgentCard(
            "contrib-demo",
            "Contrib Demo",
            "1.0.0",
            SecurityPolicy(upstream_base_url="https://u.test/v1"),
        )
        registry.register(card)
        mgr = BattleManager(registry)
        battle = mgr.create("contrib-demo")
        import asyncio

        asyncio.run(mgr.execute(battle.battle_id, get_pack(loaded[0])))
        done = mgr.get(battle.battle_id)
        assert done.status == "completed"
        assert done.summary["total_probes"] == len(get_pack(loaded[0]))
