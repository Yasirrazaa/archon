"""SKILL.md supply-chain scanner.

Scans agent skill definitions (e.g. SKILL.md files) for prompt-injection
phrases, suspicious download URLs, hardcoded secrets, remote instruction
fetching, and dangerous execution commands. Fully static and offline.

Lifecycle stages (Storage/Retrieval/Evolution) follow the six-stage model of
SkillSec-Eval (arXiv:2607.13987): manifest/body consistency (storage),
Sybil/stuffing clustering (retrieval), and version-diff escalation checks
(evolution).
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


# ---------------------------------------------------------------------------
# Lifecycle stage checks (SkillSec-Eval, arXiv:2607.13987)
# ---------------------------------------------------------------------------

# operation class -> body keyword pattern
_OP_PATTERNS: dict[str, re.Pattern[str]] = {
    "network": _ci(r"http|url|fetch|request"),
    "filesystem": _ci(r"write|delete|rm|path"),
    "exec": _ci(r"bash|subprocess|eval"),
    "secrets": _ci(r"key|token|credential"),
}

_WORD_RE = re.compile(r"[a-z0-9]+")


def jaccard(a: set[str], b: set[str]) -> float:
    """Token-set Jaccard similarity; two empty sets are defined as 0.0."""
    if not a and not b:
        return 0.0
    union = a | b
    if not union:
        return 0.0
    return len(a & b) / len(union)


def check_manifest_consistency(skill: dict) -> list[Finding]:
    """Storage stage: flag body operations missing from declared_permissions."""
    declared = set(skill.get("declared_permissions") or [])
    body = skill.get("body", "")
    used = {op for op, pattern in _OP_PATTERNS.items() if pattern.search(body)}
    findings = [
        Finding(
            "manifest_mismatch",
            "high",
            f"body uses '{op}' operations not declared in permissions manifest",
        )
        for op in sorted(used - declared)
    ]
    return _sorted(findings)


class _UnionFind:
    def __init__(self, n: int):
        self.parent = list(range(n))

    def find(self, i: int) -> int:
        while self.parent[i] != i:
            self.parent[i] = self.parent[self.parent[i]]
            i = self.parent[i]
        return i

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[max(ra, rb)] = min(ra, rb)


def cluster_similarity(
    skills: list[dict], threshold: float = 0.85
) -> list[Finding]:
    """Retrieval stage: group near-duplicate descriptions (Sybil/stuffing).

    Uses token-set Jaccard over descriptions with union-find grouping; each
    resulting cluster of >=2 members yields one ``sybil_cluster`` finding.
    """
    token_sets = [
        frozenset(_WORD_RE.findall(s.get("description", "").lower())) for s in skills
    ]
    uf = _UnionFind(len(skills))
    for i in range(len(skills)):
        for j in range(i + 1, len(skills)):
            if jaccard(set(token_sets[i]), set(token_sets[j])) >= threshold:
                uf.union(i, j)
    groups: dict[int, list[str]] = {}
    for idx, skill in enumerate(skills):
        groups.setdefault(uf.find(idx), []).append(skill.get("name", ""))
    findings = [
        Finding("sybil_cluster", "medium", "sybil/stuffing cluster: " + " ".join(members))
        for members in groups.values()
        if len(members) >= 2
    ]
    return _sorted(findings)


def diff_versions(old: dict, new: dict) -> list[Finding]:
    """Evolution stage: flag permission escalation, description drift, new exec.

    - added permission vs old manifest -> high ``permission_escalation``
    - description with >30% novel tokens -> medium ``description_drift``
    - exec keyword appearing where absent before -> high
      ``new_execution_capability``
    """
    findings: list[Finding] = []
    old_perms = set(old.get("declared_permissions") or [])
    new_perms = set(new.get("declared_permissions") or [])
    for perm in sorted(new_perms - old_perms):
        findings.append(
            Finding(
                "permission_escalation",
                "high",
                f"permission '{perm}' added without prior declaration",
            )
        )

    old_desc = set(_WORD_RE.findall(old.get("description", "").lower()))
    new_desc = set(_WORD_RE.findall(new.get("description", "").lower()))
    fresh = new_desc - old_desc
    if new_desc and len(fresh) / len(new_desc) > 0.3:
        findings.append(
            Finding(
                "description_drift",
                "medium",
                "description drifted beyond trivial edit (>30% new tokens)",
            )
        )

    exec_pattern = _OP_PATTERNS["exec"]
    old_body = old.get("body", "")
    new_body = new.get("body", "")
    if not exec_pattern.search(old_body) and exec_pattern.search(new_body):
        findings.append(
            Finding(
                "new_execution_capability",
                "high",
                "execution keywords appeared in body where none existed before",
            )
        )
    return _sorted(findings)


def lifecycle_scan(
    skill_or_corpus: dict | list[dict], previous_version: dict | None = None
) -> dict[str, list[Finding]]:
    """Aggregate lifecycle checks into {'storage','retrieval','evolution','authoring'}.

    Accepts a single skill dict or a corpus (list of dicts). When
    *previous_version* is supplied the evolution diff runs against it.
    """
    skills = [skill_or_corpus] if isinstance(skill_or_corpus, dict) else list(skill_or_corpus)
    report: dict[str, list[Finding]] = {
        "storage": [],
        "retrieval": [],
        "evolution": [],
        "authoring": [],
    }
    for skill in skills:
        report["storage"].extend(check_manifest_consistency(skill))
        report["authoring"].extend(
            scan_skill(SkillDefinition(name=skill.get("name", ""), body=skill.get("body", "")))
        )
    report["retrieval"].extend(cluster_similarity(skills))
    if previous_version is not None:
        for skill in skills:
            report["evolution"].extend(diff_versions(previous_version, skill))
    return {stage: _sorted(findings) for stage, findings in report.items()}
