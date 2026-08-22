"""Sprint B1 — live behavioral MCP server scanning.

Connects to a *running* MCP server over Streamable HTTP, enumerates its real
tools, and runs the mcp_scan pattern engine against the live tool metadata.
This is what static config scanners (Snyk Agent Scan) cannot do: the deployed
server may differ from its manifest. Session injection keeps tests offline and
the module importable without a live server.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from archon_core.targets.mcp_scan import _DESCRIPTION_PATTERNS, Finding, _snippet


@dataclass
class LiveScanResult:
    """Outcome of scanning one running MCP server."""

    url: str
    server_info: str | None = None
    tool_count: int = 0
    tools_scanned: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)

    @property
    def has_high(self) -> bool:
        return any(f.severity.value == "high" for f in self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "url": self.url,
            "server_info": self.server_info,
            "tool_count": self.tool_count,
            "tools_scanned": list(self.tools_scanned),
            "findings": [f.__dict__ for f in self.findings],
            "errors": list(self.errors),
            "has_high": self.has_high,
        }


def scan_live_tools(url: str, tools: list[Any]) -> tuple[list[Finding], list[str]]:
    """Pattern-scan live tool metadata; returns (findings, per-tool errors)."""
    findings: list[Finding] = []
    errors: list[str] = []
    for tool in tools:
        try:
            name = getattr(tool, "name", None) or "<unnamed>"
            desc = str(getattr(tool, "description", "") or "")
        except Exception as exc:  # malformed tool object
            errors.append(f"unreadable tool metadata: {exc}")
            continue
        for pattern, severity, category, description in _DESCRIPTION_PATTERNS:
            m = pattern.search(desc)
            if m:
                findings.append(Finding(
                    tool=str(name), category=category, severity=severity,
                    description=description, evidence=_snippet(desc, m),
                ))
    return findings, errors


async def scan_live_mcp(
    url: str,
    session: Any | None = None,
    session_factory: Any | None = None,
) -> LiveScanResult:
    """Scan a running MCP server.

    Pass `session` (already-initialized ClientSession-like) for offline use,
    or `session_factory` (async callable -> async context manager yielding a
    session). Neither given => real Streamable HTTP connection to `url`.
    """
    result = LiveScanResult(url=url)
    if session is None:
        try:
            from mcp import ClientSession
            from mcp.client.streamable_http import streamablehttp_client
        except ImportError as exc:
            result.errors.append(f"mcp client unavailable: {exc}")
            return result

        async def _default_factory():
            cm = streamablehttp_client(url)
            read, write, _ = await cm.__aenter__()
            session_cm = ClientSession(read, write)
            s = await session_cm.__aenter__()
            await s.initialize()
            return s

        session_factory = session_factory or _default_factory
        try:
            session = await session_factory()
        except Exception as exc:
            result.errors.append(f"connection failed: {exc}")
            return result

    try:
        init = await session.initialize()
        result.server_info = str(
            getattr(getattr(init, "serverInfo", None), "name", None) or ""
        ) or None
    except Exception as exc:
        result.errors.append(f"initialize failed: {exc}")
        return result

    try:
        listing = await session.list_tools()
        tools = list(getattr(listing, "tools", []) or [])
    except Exception as exc:
        result.errors.append(f"list_tools failed: {exc}")
        return result

    result.tool_count = len(tools)
    result.tools_scanned = [str(getattr(t, "name", "<unnamed>")) for t in tools]
    findings, errors = scan_live_tools(url, tools)
    result.findings.extend(findings)
    result.errors.extend(errors)
    return result
