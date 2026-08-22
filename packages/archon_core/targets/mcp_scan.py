"""Static MCP tool-poisoning scanner.

Scans MCP server configurations and tool definitions for the poisoning
patterns documented by OWASP/Invariant research: hidden instructions inside
tool descriptions, exfiltration endpoints, encoded exec payloads in launch
arguments, and cross-tool override phrases. Behavioral (runtime) MCP testing
lands on top of this via TargetAdapter; static scanning is fully offline.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from enum import Enum
from typing import Any

from archon_core.observability.scrubbing import AttributeScrubber


class Severity(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass(frozen=True)
class Finding:
    tool: str
    category: str
    severity: Severity
    description: str
    evidence: str  # redacted snippet

    def __dict__(self):  # pragma: no cover - convenience for json.dumps
        return {
            "tool": self.tool,
            "category": self.category,
            "severity": self.severity.value,
            "description": self.description,
            "evidence": self.evidence,
        }


_DESCRIPTION_PATTERNS = [
    (re.compile(r"<important\b", re.I), Severity.HIGH, "hidden_instruction",
     "Hidden '<IMPORTANT>' instruction block inside tool description"),
    (re.compile(r"\bignore\s+(all\s+|any\s+)?(previous|prior|other)\s+(instructions|tools|rules)\b", re.I),
     Severity.HIGH, "cross_tool_override",
     "Cross-tool instruction override phrase"),
    (re.compile(r"\bsystem\s+(prompt|message)\b", re.I),
     Severity.MEDIUM, "system_reference",
     "References to system prompt inside tool description"),
    (re.compile(r"https?://[^\s]+", re.I),
     Severity.HIGH, "exfiltration_endpoint",
     "Outbound URL in tool description (possible exfiltration channel)"),
    (re.compile(r"\b(read|send|post|exfiltrat\w*|upload)\b[^.]*\b(file|env|credentials?|keys?|token)\b", re.I),
     Severity.HIGH, "exfil_instructions",
     "Instructions referencing reading/sending files or credentials"),
]

_ARGS_PATTERNS = [
    (re.compile(r"base64.*decod|fromhex", re.I), Severity.HIGH, "encoded_exec",
     "Encoded payload decoding in launch args"),
    (re.compile(r"\beval\s*\(|\bexec\s*\(", re.I), Severity.HIGH, "dynamic_exec",
     "Dynamic eval/exec in launch args"),
    (re.compile(r"curl[^|]*\|\s*(sh|bash)", re.I), Severity.HIGH, "remote_exec",
     "Pipe-to-shell pattern in launch args"),
]

_scrubber = AttributeScrubber()


def _snippet(text: str, match: re.Match, width: int = 60) -> str:
    start = max(0, match.start() - width // 2)
    end = min(len(text), match.end() + width // 2)
    raw = text[start:end].replace("\n", " ")
    return _scrubber.scrub_value(raw)


def scan_mcp_config(config: dict[str, Any]) -> list[Finding]:
    findings: list[Finding] = []
    servers = config.get("mcpServers", config.get("servers", {}))
    for server_name, server in servers.items():
        if not isinstance(server, dict):
            continue
        args_text = " ".join(str(a) for a in server.get("args", []))
        for pattern, severity, category, description in _ARGS_PATTERNS:
            m = pattern.search(args_text)
            if m:
                findings.append(Finding(
                    tool=f"(server: {server_name})", category=category, severity=severity,
                    description=description, evidence=_snippet(args_text, m),
                ))
        for tool in server.get("tools", []) or []:
            if not isinstance(tool, dict):
                continue
            tool_name = tool.get("name", "<unnamed>")
            desc = str(tool.get("description", ""))
            for pattern, severity, category, description in _DESCRIPTION_PATTERNS:
                m = pattern.search(desc)
                if m:
                    findings.append(Finding(
                        tool=tool_name, category=category, severity=severity,
                        description=description, evidence=_snippet(desc, m),
                    ))
    return findings


class McpConfigScanner:
    def scan_dict(self, config: dict[str, Any]) -> list[Finding]:
        return scan_mcp_config(config)

    def scan_file(self, path: str) -> list[Finding]:
        with open(path, encoding="utf-8") as fh:
            return scan_mcp_config(json.load(fh))
