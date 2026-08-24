"""Local agent-config client discovery (agent-scan well_known_clients port).

Scans the local machine for well-known AI coding-agent configuration files
(Claude Code, Claude Desktop, Cursor, VS Code, Windsurf, Gemini CLI,
OpenCode) so security tooling can enumerate which agents are configured
locally. Discovery is strictly read-only and never raises on permission
errors — unreadable paths are skipped.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Callable
from dataclasses import dataclass


@dataclass(frozen=True)
class ClientSpec:
    """A known agent client and its config-file locations.

    Attributes:
        name: Stable client identifier (e.g. ``"claude_code"``).
        config_paths: Platform key -> posix-style absolute path patterns.
            Keys are ``"darwin"``, ``"linux"``, or ``"default"`` (used when
            no exact platform match exists). Patterns start with ``~/`` and
            are expanded at discovery time.
    """

    name: str
    config_paths: dict[str, list[str]]


@dataclass(frozen=True)
class DiscoveredClient:
    """A client whose config was found on this machine."""

    name: str
    found_paths: list[str]


KNOWN_CLIENTS: list[ClientSpec] = [
    ClientSpec(
        name="claude_code",
        config_paths={
            "default": ["~/.claude.json", "~/.claude/settings.json"],
        },
    ),
    ClientSpec(
        name="claude_desktop",
        config_paths={
            "darwin": ["~/Library/Application Support/Claude/claude_desktop_config.json"],
            "linux": ["~/.config/Claude/claude_desktop_config.json"],
            "default": ["~/.config/Claude/claude_desktop_config.json"],
        },
    ),
    ClientSpec(
        name="cursor",
        config_paths={
            "default": ["~/.cursor/mcp.json"],
        },
    ),
    # VS Code MCP servers may also live in settings.json's "mcp" section;
    # these paths cover the common install locations we can probe read-only.
    ClientSpec(
        name="vscode",
        config_paths={
            "darwin": [
                "~/Library/Application Support/Code/User/settings.xml",
                "~/.vscode-server/data",
            ],
            "linux": ["~/.config/Code/User/settings.xml", "~/.vscode-server/data"],
            "default": ["~/.config/Code/User/settings.xml", "~/.vscode-server/data"],
        },
    ),
    ClientSpec(
        name="windsurf",
        config_paths={
            "default": ["~/.codeium/windsurf/mcp_config.json"],
        },
    ),
    ClientSpec(
        name="gemini_cli",
        config_paths={
            "default": ["~/.gemini/settings.json"],
        },
    ),
    ClientSpec(
        name="opencode",
        config_paths={
            "default": ["~/.config/opencode/config.json"],
        },
    ),
]

def _platform_key() -> str:
    if sys.platform == "darwin":
        return "darwin"
    return "linux"


def _patterns_for(spec: ClientSpec) -> list[str]:
    platform = _platform_key()
    paths = spec.config_paths.get(platform) or spec.config_paths.get("default") or []
    return list(paths)


def _expand(pattern: str, root: str | None) -> str:
    if root:
        if not root.endswith("/"):
            root += "/"
        return root + pattern.removeprefix("~/")
    return os.path.expanduser(pattern)


def discover_clients(
    root: str | None = None,
    exists: Callable[[str], bool] | None = None,
) -> list[DiscoveredClient]:
    """Discover locally configured agent clients.

    Args:
        root: Optional home-directory override used instead of ``~`` expansion
            (primarily for tests). Falsy values fall back to ``expanduser``.
        exists: Injectable existence predicate (defaults to ``os.path.exists``,
            resolved at call time so monkeypatching works).

    Returns:
        Clients with at least one existing config path. Paths whose existence
        check raises (e.g. permission errors) are skipped, never propagated.
    """
    probe = exists or os.path.exists
    found: list[DiscoveredClient] = []
    for spec in KNOWN_CLIENTS:
        hits: list[str] = []
        for pattern in _patterns_for(spec):
            candidate = _expand(pattern, root)
            try:
                if probe(candidate):
                    hits.append(candidate)
            except OSError:
                continue
        if hits:
            found.append(DiscoveredClient(name=spec.name, found_paths=hits))
    return found


def summarize_discovery(found: list[DiscoveredClient]) -> dict:
    """Summarize discovery results as counts plus a per-client path map."""
    by_client: dict[str, list[str]] = {}
    for client in found:
        by_client.setdefault(client.name, []).extend(client.found_paths)
    return {
        "clients_found": len(found),
        "total_paths": sum(len(paths) for paths in by_client.values()),
        "by_client": by_client,
    }
