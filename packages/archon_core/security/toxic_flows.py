"""Toxic-flow capability graph and cross-server tool shadowing (W015-W020/E002).

Builds a capability graph over MCP tool descriptions and flags dangerous
combinations (toxic flows) plus E002 shadowing, where one server's tool
description references another server's tool names to hijack selection.
Fully static and offline.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class ToolCapability:
    server: str
    tool: str
    touches_untrusted_content: bool = False
    accesses_sensitive_data: bool = False
    destructive: bool = False
    network_egress: bool = False
    description: str = ""


@dataclass(frozen=True)
class ToxicFlow:
    severity: str
    reason: str
    servers: tuple[str, ...]


@dataclass(frozen=True)
class ShadowFinding:
    server: str
    tool: str
    shadowed_server: str
    shadowed_tool: str


_UNTRUSTED = re.compile(r"\bfetch|\bretrieve|\bread.*\bweb|\bsearch", re.IGNORECASE)
_SENSITIVE = re.compile(
    r"\bpassword|\bsecret|\btoken|\bpii\b|\bcredential", re.IGNORECASE
)
_DESTRUCTIVE = re.compile(
    r"\bdelete|\bdrop\b|\bpurge|\bwipe|\bsend[_\s]money|\btransfer", re.IGNORECASE
)
_EGRESS = re.compile(r"\bhttp|\bpost\b|\bupload|\bwebhook", re.IGNORECASE)


def classify_tool(description: str, server: str = "", tool: str = "") -> ToolCapability:
    """Infer a ToolCapability from a tool description via keyword heuristics."""
    return ToolCapability(
        server=server,
        tool=tool,
        touches_untrusted_content=bool(_UNTRUSTED.search(description)),
        accesses_sensitive_data=bool(_SENSITIVE.search(description)),
        destructive=bool(_DESTRUCTIVE.search(description)),
        network_egress=bool(_EGRESS.search(description)),
        description=description,
    )


_REASON_UNTRUSTED_DESTRUCTIVE = "untrusted content can trigger destruction"
_REASON_EXFIL = "sensitive data can be exfiltrated after touching untrusted content"
_REASON_SENSITIVE_EGRESS = "sensitive data can be sent off-network"


def _servers_of(caps: list[ToolCapability], pred) -> list[str]:
    return sorted({c.server for c in caps if c.server and pred(c)})


def toxic_flows(caps: list[ToolCapability]) -> list[ToxicFlow]:
    """Flag dangerous capability combinations across the graph, deduplicated."""
    flows: dict[tuple[str, str, tuple[str, ...]], ToxicFlow] = {}

    def add(severity: str, reason: str, servers: list[str]) -> None:
        if not servers:
            return
        key = (severity, reason, tuple(servers))
        flows.setdefault(key, ToxicFlow(severity, reason, list(servers)))

    has_untrusted = any(c.touches_untrusted_content for c in caps)
    has_sensitive = any(c.accesses_sensitive_data for c in caps)
    has_destructive = any(c.destructive for c in caps)
    has_egress = any(c.network_egress for c in caps)

    if has_untrusted and has_destructive:
        add("high", _REASON_UNTRUSTED_DESTRUCTIVE,
            _servers_of(caps, lambda c: c.touches_untrusted_content or c.destructive))
    if has_untrusted and has_sensitive and has_egress:
        add("high", _REASON_EXFIL,
            _servers_of(caps, lambda c: c.accesses_sensitive_data or c.network_egress))
    if has_sensitive and has_egress:
        add("medium", _REASON_SENSITIVE_EGRESS,
            _servers_of(caps, lambda c: c.accesses_sensitive_data or c.network_egress))
    if has_destructive:
        add("info", "tool can perform destructive actions",
            _servers_of(caps, lambda c: c.destructive))

    return sorted(flows.values(), key=lambda f: (f.severity, f.reason))


def cross_server_shadowing(caps: list[ToolCapability]) -> list[ShadowFinding]:
    """Detect tools whose description mentions another server's tool names (E002)."""
    by_tool_name = {
        c.tool.lower(): c for c in caps if c.tool
    }
    findings: list[ShadowFinding] = []
    seen: set[tuple[str, str, str, str]] = set()
    for cap in caps:
        desc = cap.description or ""
        for other_tool, other_cap in sorted(by_tool_name.items()):
            if other_cap.server == cap.server or not desc:
                continue
            if re.search(rf"\b{re.escape(other_tool)}\b", desc, re.IGNORECASE):
                key = (cap.server, cap.tool, other_cap.server, other_cap.tool)
                if key not in seen:
                    seen.add(key)
                    findings.append(
                        ShadowFinding(cap.server, cap.tool,
                                      other_cap.server, other_cap.tool)
                    )
    return findings
