"""SKILL.md supply-chain scanner.

Scans agent skill definitions (e.g. SKILL.md files) for prompt-injection
phrases, suspicious download URLs, hardcoded secrets, remote instruction
fetching, and dangerous execution commands. Fully static and offline.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

_SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2}


@dataclass(frozen=True)
class SkillDefinition:
    name: str
    body: str
    source_path: str | None = None


@dataclass(frozen=True)
class Finding:
    code: str
    severity: str
    message: str


def _ci(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE)


# (code, severity, message, pattern)
_RULES: tuple[tuple[str, str, str, re.Pattern[str]], ...] = (
    # E004 skill-injection
    ("E004", "high", "instruction-override phrase in skill body",
     _ci(r"\bignore\s+previous\b")),
    ("E004", "high", "instruction-override phrase in skill body",
     _ci(r"\bdisregard\b.{0,40}\binstructions\b")),
    ("E004", "high", "fake system tag in skill body", _ci(r"\[SYSTEM\]|<system>")),
    ("E004", "high", "persona-override phrase in skill body",
     _ci(r"\byou\s+are\s+now\b|\bact\s+as\b")),
    # E005 suspicious-download-url
    ("E005", "high", "download of executable script from remote host",
     _ci(r"\b(?:curl|wget)\b[^\n]*\.(?:sh|py|bin)\b")),
    ("E005", "high", "direct URL to executable script file",
     _ci(r"https?://\S+\.(?:sh|py|bin)\b")),
    ("E005", "high", "pip install from non-PyPI host",
     _ci(r"\bpip\s+install\b[^\n]*https?://(?!pypi\.org)[^\s/]*")),
    # W007 hardcoded-secret
    ("W007", "high", "hardcoded API key or token",
     _ci(r"sk-or-v1-|sk-ant-|AKIA[0-9A-Z]{16}|ghp_|xox[bap]-")),
    ("W007", "high", "embedded private key material",
     _ci(r"BEGIN PRIVATE KEY")),
    # W012 remote-instruction-fetch
    ("W012", "medium", "fetches instructions at runtime from remote host",
     _ci(r"\bhttp\.get\b|\brequests\.get\s*\(|fetch\(.*instruction|"
         r"load.*remote.*prompt")),
    # W013 excessive-execution
    ("W013", "high", "dangerous shell execution command",
     _ci(r"\brm\s+-rf\b|\bsudo\s+\S|\bchmod\s+777\b|curl[^|\n]*\|\s*(?:sh|bash)\b")),
)


def scan_skill(skill: SkillDefinition) -> list[Finding]:
    """Scan a single skill body and return findings sorted deterministically."""
    matched_codes: dict[str, Finding] = {}
    for code, severity, message, pattern in _RULES:
        if pattern.search(skill.body):
            matched_codes.setdefault(code, Finding(code, severity, message))
    return _sorted(matched_codes.values())


def scan_skill_dir(path: Path | str) -> list[Finding]:
    """Walk *.md files under *path* and scan each; never raises on unreadable files."""
    findings: list[Finding] = []
    for md_path in _walk_md(Path(path)):
        try:
            body = md_path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError, ValueError):
            findings.append(
                Finding("W000", "low", f"unreadable skill file: {md_path.name}")
            )
            continue
        findings.extend(
            scan_skill(
                SkillDefinition(
                    name=md_path.stem, body=body, source_path=str(md_path)
                )
            )
        )
    return _sorted(findings)


def _walk_md(root: Path) -> Iterator[Path]:
    if not root.is_dir():
        return
    for md_path in sorted(root.rglob("*.md")):
        if md_path.is_file():
            yield md_path


def _sorted(findings) -> list[Finding]:
    return sorted(findings, key=lambda f: (_SEVERITY_RANK[f.severity], f.code))
