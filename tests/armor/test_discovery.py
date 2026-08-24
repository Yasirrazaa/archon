"""Tests for local agent-config client discovery (sprint 80).

Discovery must be:
- pure/read-only (no filesystem writes anywhere),
- testable via an injectable ``exists`` predicate and ``root`` home override,
- never raise on permission errors (skip the offending path instead).
"""

from __future__ import annotations

import builtins
import os

import pytest
from archon_core.discovery import (
    KNOWN_CLIENTS,
    ClientSpec,
    DiscoveredClient,
    discover_clients,
    summarize_discovery,
)

_ALL_PATTERNS = [
    pattern for spec in KNOWN_CLIENTS for paths in spec.config_paths.values() for pattern in paths
]


def _applicable_patterns(spec: ClientSpec) -> list[str]:
    key = "darwin" if os.sys.platform == "darwin" else "linux"  # noqa: SLF001
    return spec.config_paths.get(key) or spec.config_paths.get("default") or []


class TestKnownClients:
    def test_at_least_six_known_clients(self):
        assert len(KNOWN_CLIENTS) >= 6

    def test_client_specs_have_unique_names(self):
        names = [spec.name for spec in KNOWN_CLIENTS]
        assert len(names) == len(set(names))

    def test_required_client_names_present(self):
        names = {spec.name for spec in KNOWN_CLIENTS}
        assert {
            "claude_code",
            "claude_desktop",
            "cursor",
            "vscode",
            "windsurf",
            "gemini_cli",
            "opencode",
        } <= names

    def test_claude_desktop_has_platform_variants(self):
        desktop = next(s for s in KNOWN_CLIENTS if s.name == "claude_desktop")
        assert "darwin" in desktop.config_paths
        assert any(k != "darwin" for k in desktop.config_paths)

    def test_all_patterns_are_posix_absolute_with_home_marker(self):
        assert _ALL_PATTERNS
        for pattern in _ALL_PATTERNS:
            assert pattern.startswith("~/")
            assert "\\" not in pattern


class TestDiscoverClients:
    def test_root_none_expands_tilde(self, monkeypatch):
        monkeypatch.setattr(os.path, "exists", lambda p: True)
        found = discover_clients()
        assert found
        for client in found:
            for path in client.found_paths:
                assert "~" not in path
                assert path.startswith(os.path.expanduser("~") + "/")

    def test_root_overrides_home_expansion(self):
        root = "/tmp/opencode/fakehome80"
        seen: list[str] = []

        def fake_exists(path: str) -> bool:
            seen.append(path)
            return True

        found = discover_clients(root=root, exists=fake_exists)
        assert seen
        assert all(p.startswith(root + "/") for p in seen)
        total = sum(len(c.found_paths) for c in found)
        expected = sum(len(_applicable_patterns(s)) for s in KNOWN_CLIENTS)
        assert total == expected

    def test_exists_true_finds_every_pattern(self):
        found = discover_clients(exists=lambda p: True)
        assert [c.name for c in found] == [s.name for s in KNOWN_CLIENTS]
        expected = sum(len(_applicable_patterns(s)) for s in KNOWN_CLIENTS)
        assert sum(len(c.found_paths) for c in found) == expected

    def test_exists_false_finds_nothing(self):
        assert discover_clients(exists=lambda p: False) == []

    def test_permission_error_is_skipped_not_raised(self):
        def denied(_path: str) -> bool:
            raise PermissionError(13, "no peeking")

        assert discover_clients(exists=denied) == []

    def test_oserror_from_predicate_is_skipped_for_other_paths(self):
        def selective(path: str) -> bool:
            if path.endswith("settings.json"):
                raise OSError("locked")
            return True

        found = discover_clients(exists=selective)
        assert found
        for client in found:
            assert all(not p.endswith("settings.json") for p in client.found_paths)

    def test_partial_existence_returns_subset(self):
        applicable = [
            p for s in KNOWN_CLIENTS for p in _applicable_patterns(s)
        ]
        existing = {p.replace("~", "/tmp/opencode/fakehome80", 1) for p in applicable[:3]}
        found = discover_clients(
            root="/tmp/opencode/fakehome80", exists=lambda p: p in existing
        )
        assert sum(len(c.found_paths) for c in found) == 3

    def test_result_types(self):
        found = discover_clients(exists=lambda p: True)
        assert all(isinstance(c, DiscoveredClient) for c in found)
        assert all(isinstance(s, ClientSpec) for s in KNOWN_CLIENTS)


class TestSummarizeDiscovery:
    def test_summary_math(self):
        found = discover_clients(exists=lambda p: True)
        summary = summarize_discovery(found)
        assert summary["clients_found"] == len(found)
        assert summary["total_paths"] == sum(len(c.found_paths) for c in found)
        assert set(summary["by_client"]) == {c.name for c in found}

    def test_summary_empty_input(self):
        assert summarize_discovery([]) == {
            "clients_found": 0,
            "total_paths": 0,
            "by_client": {},
        }

    def test_summary_by_client_lists_paths(self):
        root = "/tmp/opencode/fakehome80"
        found = discover_clients(root=root, exists=lambda p: True)
        summary = summarize_discovery(found)
        for client in found:
            assert summary["by_client"][client.name] == [
                p for p in client.found_paths
            ]
            assert all(p.startswith(root + "/") for p in summary["by_client"][client.name])


class TestNoFilesystemWrites:
    def test_discovery_never_opens_files_for_writing(self, monkeypatch):
        real_open = builtins.open

        def guard(file, mode="r", *args, **kwargs):  # noqa: ANN001, A002
            if any(m in str(mode) for m in ("w", "a", "x", "+")):
                raise AssertionError(f"discovery attempted a write: {file!r} mode={mode!r}")
            return real_open(file, mode, *args, **kwargs)

        monkeypatch.setattr(builtins, "open", guard)
        found = discover_clients(root="/tmp/opencode/fakehome80", exists=lambda p: True)
        summarize_discovery(found)


@pytest.mark.parametrize("root", ["", "/tmp/opencode"])
def test_empty_root_falls_back_to_expanduser(monkeypatch, root):
    monkeypatch.setattr(os.path, "exists", lambda p: True)
    found = discover_clients(root=root)
    assert sum(len(c.found_paths) for c in found) > 0
