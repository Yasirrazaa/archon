"""Shadow mode defense evaluation.

Armor evaluates every defense layer and reports *would-block* verdicts
WITHOUT enforcing them, so enterprises can measure block rates on mirrored
traffic before taking enforcement risk. The evaluator runs the exact same
``DefensePipeline`` the enforcement path uses — on a deep copy of the
exchange — so verdicts are faithful while the caller's exchange (and any
downstream enforcement decision) is never mutated.
"""

from __future__ import annotations

import copy
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

from archon_core.defenses.base import DefensePipeline
from archon_core.models import Exchange

# Metadata namespaces inspected for findings, in deterministic order.
_FINDING_KEYS = ("normalization", "threat", "execution_mode")


@dataclass
class ShadowVerdict:
    """Outcome of a shadow-mode evaluation: what enforcement WOULD have done."""

    would_block: bool
    block_reason: str | None = None
    layer: str | None = None
    findings: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "would_block": self.would_block,
            "block_reason": self.block_reason,
            "layer": self.layer,
            "findings": [dict(finding) for finding in self.findings],
        }


class ShadowEvaluator:
    """Runs the enforcement pipeline in observe-only mode.

    Args:
        defense_pipeline: The same ``DefensePipeline`` used by enforcement.
        tracer: Optional tracer; records a ``shadow.evaluate`` span per run.
        audit_sink: Optional callable receiving one JSONL line (with trailing
            newline) per evaluation, so operators can diff shadow vs enforce
            rates later.
    """

    def __init__(
        self,
        defense_pipeline: DefensePipeline,
        tracer: Any | None = None,
        audit_sink: Callable[[str], None] | None = None,
    ) -> None:
        self._pipeline = defense_pipeline
        self._tracer = tracer
        self._audit_sink = audit_sink

    async def evaluate(self, exchange: Exchange) -> ShadowVerdict:
        try:
            result = await self._pipeline.run(copy.deepcopy(exchange))
            verdict = ShadowVerdict(
                would_block=result.blocked,
                block_reason=result.block_reason,
                layer=self._attributed_layer(result.block_reason),
                findings=self._collect_findings(result),
            )
        except Exception:
            # Shadow mode must never raise on hostile input; a pipeline
            # failure is reported as an inconclusive shadow-error.
            verdict = ShadowVerdict(would_block=False, block_reason="shadow-error")
        self._record(exchange, verdict)
        return verdict

    @staticmethod
    def _attributed_layer(block_reason: str | None) -> str | None:
        if not block_reason:
            return None
        return block_reason.split(":")[0].split()[0]

    @staticmethod
    def _collect_findings(result: Exchange) -> list[dict[str, Any]]:
        findings: list[dict[str, Any]] = []
        for key in _FINDING_KEYS:
            value = result.metadata.get(key)
            if isinstance(value, dict):
                findings.append({"source": key, **value})
        return findings

    def _record(self, exchange: Exchange, verdict: ShadowVerdict) -> None:
        del exchange  # recorded verdicts are exchange-independent by design
        if self._tracer is not None:
            span = self._tracer.start_span(
                "shadow.evaluate", attributes={"component": "shadow"}
            )
            self._tracer.end_span(
                span,
                attributes={"would_block": verdict.would_block, "layer": verdict.layer},
            )
        if self._audit_sink is not None:
            record = {
                "ts": datetime.now(timezone.utc).isoformat(),
                "would_block": verdict.would_block,
                "layer": verdict.layer,
                "block_reason": verdict.block_reason,
            }
            self._audit_sink(json.dumps(record, separators=(",", ":")) + "\n")


__all__ = ["ShadowEvaluator", "ShadowVerdict"]
