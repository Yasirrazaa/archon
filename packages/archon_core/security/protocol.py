"""Protocol-layer security for MCP registries and A2A agent cards.

Sprint E2.5-13. Hardens the two protocol surfaces where trust is granted
once and rarely re-checked:

- **MCP registry entries**: the MCP registry preview (July 2026) requires
  provenance metadata but scans NO code, so a verified-provenance entry can
  still carry a poisoned description. This module vets entries for missing
  provenance verification, prompt-injection markers, and stuffing.
- **A2A AgentCards**: the A2A v1.0 spec §8.4 defines JWS signing served at
  ``/.well-known/agent-card.json``, but cards are unsigned-by-default in
  practice. :func:`verify_agent_card` validates card shape and flags
  unsigned cards only when a caller opts into requiring signatures.

Drift monitoring (:class:`DriftMonitor`) closes the re-validation gap behind
CVE-2025-54136 "MCPoison" (CVSS 8.8): tool definitions approved once are
never re-validated afterwards, so a rug pull — a previously-approved tool's
hash silently changing, as in the postmark-mcp backdoor (15 clean releases,
then a malicious one) — goes unnoticed. The ETDI proposal (arXiv:2506.01333)
reaches the same goal with signed versioned definitions; hash pinning here is
the lightweight offline counterpart.

Deterministic and fully offline; no LLM or network calls.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field

# Substrings that mark prompt-injection attempts inside registry entry
# descriptions. Matched case-insensitively against the lowercased text.
_INJECTION_MARKERS = (
    "ignore previous",
    "system prompt",
    "[system",
)

# Descriptions beyond this length are flagged as low-severity stuffing:
# long descriptions dilute agent attention and hide injected directives.
_MAX_DESCRIPTION_LENGTH = 500


@dataclass(frozen=True)
class ToolFingerprint:
    """Hashable identity of a tool definition's approver-visible surface.

    Canonicalization matches the Sprint E2.5-13 spec: sha256 over
    ``f"{name}:{description}:{version}"`` — the same fields an approver
    signs off on, colon-separated so field boundaries cannot be blurred
    by concatenation ambiguity.
    """

    tool_name: str
    description: str
    version: str

    def hash(self) -> str:
        """Stable sha256 hex digest over the definition surface."""
        material = f"{self.tool_name}:{self.description}:{self.version}"
        return hashlib.sha256(material.encode("utf-8")).hexdigest()


@dataclass
class DriftReport:
    """Result of comparing current tool fingerprints against pinned baselines.

    ``changed`` is the rug-pull signal (CVE-2025-54136): a previously-approved
    tool whose hash no longer matches its approval-time pin. Hashes are
    truncated to 12 hex chars — enough to correlate across reports without
    dumping full digests into logs.
    """

    server_name: str
    unchanged: list[str] = field(default_factory=list)
    changed: list[tuple[str, str, str]] = field(default_factory=list)
    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)

    @property
    def drifted(self) -> bool:
        """True when anything changed relative to the baseline."""
        return bool(self.changed or self.added or self.removed)


class DriftMonitor:
    """Pins per-server tool-hash baselines and diffs later observations.

    ``register`` records what was approved; ``check`` re-validates a fresh
    fingerprint list against that pin — the step real MCP clients skip.
    """

    def __init__(self) -> None:
        self._baselines: dict[str, dict[str, str]] = {}

    def register(self, server_name: str, fingerprints: list[ToolFingerprint]) -> None:
        """Pin baseline hashes for a server at approval time."""
        self._baselines[server_name] = {
            fp.tool_name: fp.hash() for fp in fingerprints
        }

    def check(
        self, server_name: str, fingerprints: list[ToolFingerprint]
    ) -> DriftReport:
        """Diff current fingerprints against the server's pinned baseline."""
        baseline = self._baselines.get(server_name)
        if baseline is None:
            raise KeyError(
                f"no baseline registered for server: {server_name!r}; "
                "call register() before check()"
            )
        current = {fp.tool_name: fp.hash() for fp in fingerprints}

        unchanged = sorted(
            name for name in current if name in baseline and baseline[name] == current[name]
        )
        changed = [
            (name, baseline[name][:12], current[name][:12])
            for name in sorted(set(baseline) & set(current))
            if baseline[name] != current[name]
        ]
        added = sorted(set(current) - set(baseline))
        removed = sorted(set(baseline) - set(current))

        return DriftReport(
            server_name=server_name,
            unchanged=unchanged,
            changed=changed,
            added=added,
            removed=removed,
        )


def verify_agent_card(card: dict | None, require_signed: bool = False) -> list[str]:
    """Validate A2A AgentCard shape; return a list of finding strings.

    Checks name presence, https-only URL transport, declared authentication
    (securitySchemes), capabilities, and — only when ``require_signed`` is
    true — JWS signatures per A2A v1.0 §8.4. Cards are unsigned-by-default
    in the wild, so signature absence is not flagged unless demanded.
    """
    if not card:
        return ["missing agent card"]

    findings: list[str] = []

    name = card.get("name")
    if not isinstance(name, str) or not name.strip():
        findings.append("missing or empty name")

    url = card.get("url")
    if not isinstance(url, str) or not url.strip():
        findings.append("missing url")
    elif url.startswith("http://"):
        findings.append("url uses insecure http:// transport")
    elif not url.startswith("https://"):
        findings.append("url must use https://")

    schemes = card.get("securitySchemes")
    if not isinstance(schemes, dict) or not schemes:
        findings.append("no authentication declared")

    capabilities = card.get("capabilities")
    if not isinstance(capabilities, dict):
        findings.append("missing capabilities")

    if require_signed and "signatures" not in card:
        findings.append("agent card unsigned (A2A §8.4 JWS recommended)")

    return findings


def scan_registry_entries(entries: list[dict]) -> list[dict]:
    """Vet MCP registry entries; return findings dicts for every problem.

    The July 2026 registry preview verifies provenance but scans no code,
    so this performs the code-side checks registries skip: unverified
    provenance (high), injection markers in descriptions (high), and
    overlong descriptions (low).
    """
    findings: list[dict] = []
    for entry in entries:
        entry_name = str(entry.get("name", "<unnamed>"))

        provenance = entry.get("provenance")
        if not isinstance(provenance, dict) or not provenance.get("verified"):
            findings.append(
                {
                    "entry": entry_name,
                    "severity": "high",
                    "reason": "no provenance verification",
                }
            )

        description = str(entry.get("description", ""))
        lowered = description.lower()
        if any(marker in lowered for marker in _INJECTION_MARKERS):
            findings.append(
                {
                    "entry": entry_name,
                    "severity": "high",
                    "reason": "prompt injection marker in description",
                }
            )

        if len(description) > _MAX_DESCRIPTION_LENGTH:
            findings.append(
                {
                    "entry": entry_name,
                    "severity": "low",
                    "reason": "unusually long description",
                }
            )

    return findings


__all__ = [
    "DriftMonitor",
    "DriftReport",
    "ToolFingerprint",
    "scan_registry_entries",
    "verify_agent_card",
]
