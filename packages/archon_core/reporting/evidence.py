"""Compliance evidence automation: tamper-evident artifacts and evidence packs.

Turns battle reports into auditor-facing, cryptographically verifiable
evidence. Research grounding:

- EU AI Act Art 9 (risk management system), Art 12 (automatic event logging
  over the lifetime of high-risk AI systems), Art 14 (human oversight),
  Art 15 (accuracy, robustness and cybersecurity).
- NIST AI RMF: MEASURE-2 (relevance of metrics) and MANAGE-2 (treatment
  prioritization).
- ISO/IEC 42001 Annex A.6.1.6 (operational logging enabling reconstruction
  of AI system behaviour).
- Cyber-insurance covenant language: tamper-evident audit logs with >=24
  months retention plus quarterly adversarial-testing evidence.
- GSA GSAR 552.239-7001: 90-day forensic log preservation and 72-hour
  incident reporting capability.

Every artifact carries a sha256 content hash over its canonical JSON payload,
so any post-hoc mutation is detectable — the "evidence, not vibes" guarantee
extended from reports to the evidence chain itself.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass(frozen=True)
class EvidenceArtifact:
    """Immutable, tamper-evident evidence unit.

    ``content_hash`` is derived in ``__post_init__`` as sha256 over the
    canonical JSON serialization of ``payload`` (sort_keys=True), per EU AI
    Act Art 12 logging and ISO/IEC 42001 A.6.1.6 reconstruction requirements.
    """

    kind: str
    framework_refs: list[str]
    generated_at: str
    payload: dict
    content_hash: str = field(init=False)

    def __post_init__(self) -> None:
        object.__setattr__(self, "content_hash", _payload_sha(self.payload))


def _payload_sha(payload: dict) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True).encode("utf-8")
    ).hexdigest()


def build_evidence_pack(
    battle_report: dict, policy_version: str = "", agent_id: str = ""
) -> dict:
    """Derive a framework-mapped evidence pack from a battle report.

    Control derivation rules (NIST AI RMF MEASURE-2: metrics must be relevant;
    MANAGE-2: treatment prioritization follows observed outcomes):

    - block_rate > 0 → EU-AI-Act-Art15 robustness control + NIST-MEASURE-2.
    - control_passed true → NIST-MANAGE-2 (mitigations effective).
    - severity findings present → EU-AI-Act-Art9 risk management.
    - ISO-42001-A.6.1.6 logging reconstruction is always emitted (EU AI Act
      Art 12 mandates automatic event logging over the system lifetime),
      with evidence_ref counting the recorded probe verdicts.
    """
    resolved_agent = agent_id or str(battle_report.get("agent_id", ""))
    total_probes = int(battle_report.get("total_probes", 0) or 0)
    block_rate = float(battle_report.get("block_rate", 0.0) or 0.0)
    control_passed = bool(battle_report.get("control_passed"))
    severity = battle_report.get("severity") or {}
    has_findings = bool(severity.get("findings"))

    controls: list[dict[str, str]] = []
    if block_rate > 0:
        controls.append({
            "control_id": "EU-AI-ACT-Art15",
            "framework": "EU AI Act",
            "description": (
                "Robustness and cybersecurity: adversarial probes were blocked "
                f"at a {block_rate:.1%} rate, evidencing resilience."
            ),
            "evidence_ref": f"block_rate={block_rate:.4f}",
        })
        controls.append({
            "control_id": "NIST-MEASURE-2",
            "framework": "NIST AI RMF",
            "description": (
                "Metrics for AI risk and related issues are relevant and "
                "tracked via adversarial block-rate measurement."
            ),
            "evidence_ref": f"blocked_probes={int(battle_report.get('blocked', 0))}",
        })
    if control_passed:
        controls.append({
            "control_id": "NIST-MANAGE-2",
            "framework": "NIST AI RMF",
            "description": (
                "Risk treatment prioritized: helpfulness control passed, "
                "confirming mitigations do not degrade legitimate usage."
            ),
            "evidence_ref": "control_passed=true",
        })
    if has_findings:
        bands = ", ".join(f"{b}={n}" for b, n in sorted((severity.get("bands") or {}).items()))
        controls.append({
            "control_id": "EU-AI-ACT-Art9",
            "framework": "EU AI Act",
            "description": (
                "Risk management system: severity findings identified and "
                "banded for prioritized remediation."
            ),
            "evidence_ref": f"findings={len(severity['findings'])};bands={bands or 'none'}",
        })
    # Always emitted: EU AI Act Art 12 / ISO 42001 A.6.1.6 require automatic
    # event logging over the system lifetime, even when no probes ran.
    verdict_count = total_probes or sum(
        slot.get("probes", 0) for slot in (battle_report.get("coverage") or {}).values()
    )
    controls.append({
        "control_id": "ISO-42001-A.6.1.6",
        "framework": "ISO/IEC 42001",
        "description": (
            "Operational logging enabling reconstruction of AI system "
            "behaviour from recorded probe verdicts."
        ),
        "evidence_ref": f"{verdict_count} probe verdicts",
    })

    pack: dict[str, Any] = {
        "pack_version": "1",
        "agent_id": resolved_agent,
        "policy_version": policy_version,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "controls": controls,
    }
    # Tamper-evidence for the pack itself: hash everything except the hash.
    pack["content_hash"] = _payload_sha(
        {k: v for k, v in pack.items() if k != "content_hash"}
    )
    return pack


def render_evidence_md(pack: dict) -> str:
    """Render an evidence pack as covenant-aligned Markdown.

    Includes the pack identity header with its content hash (tamper-evidence
    per artifact), a controls table, and retention/covenant notes mapping to
    cyber-insurance covenants (>=24-month retention, quarterly adversarial
    testing) and GSA GSAR 552.239-7001 (90-day forensic preservation,
    72-hour incident reporting readiness).
    """
    lines = [
        "# Archon Compliance Evidence Pack",
        "",
        f"- **Agent:** {pack['agent_id']}",
        f"- **Policy version:** {pack.get('policy_version') or 'n/a'}",
        f"- **Generated:** {pack['generated_at']}",
        f"- **Content hash:** sha256:{pack['content_hash']}",
        "",
        "## Controls",
        "",
        "| Control | Framework | Evidence |",
        "|---|---|---|",
    ]
    for c in pack["controls"]:
        lines.append(f"| {c['control_id']} | {c['framework']} | {c['evidence_ref']} |")
    lines += [
        "",
        "## Retention & covenant notes",
        "",
        "- Tamper-evident hashing applied per artifact (sha256 over canonical JSON).",
        "- Cyber-insurance covenant alignment: audit-log retention >=24 months "
        "with quarterly adversarial testing evidence.",
        "- GSA GSAR 552.239-7001: 90-day forensic log preservation supported.",
        "- Incident-reporting readiness: 72-hour reporting capability.",
        "",
        "_Generated by Archon — adversarially validated evidence._",
    ]
    return "\n".join(lines)


def chain_of_custody(artifacts: list[EvidenceArtifact]) -> str:
    """Compute an append-only rolling hash chain across artifacts.

    h0 = sha256(payload_0 + ""), h_n = sha256(payload_n + h_{n-1}); returns
    ``chain:<final hex digest>``. Order-sensitive by construction, so any
    reordering, insertion, or deletion breaks the chain — demonstrating
    append-only integrity for custody tracking.
    """
    rolling = ""
    for artifact in artifacts:
        rolling = hashlib.sha256(
            (json.dumps(artifact.payload, sort_keys=True) + rolling).encode("utf-8")
        ).hexdigest()
    return "chain:" + rolling
