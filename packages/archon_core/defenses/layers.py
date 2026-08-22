"""Concrete defense layers wrapping the proven AgentBeats defender logic.

Each class here adapts an existing, separately-tested implementation into
the DefenseLayer contract. Behavior lives in scenarios/security_arena/
agents/defender/ (loaded via compat); this module only adapts interfaces.
"""

from __future__ import annotations

from typing import Any

from ..compat import (
    execution_modes as em_mod,
)
from ..compat import (
    normalization as norm_mod,
)
from ..compat import (
    output_guardrails as og_mod,
)
from ..compat import (
    pyrit_defense as pd_mod,
)
from ..compat import (
    segmenter as seg_mod,
)
from ..compat import (
    threat_classifier as tc_mod,
)
from .base import DefenseLayer
from ..models import Exchange


class NormalizationLayer(DefenseLayer):
    """Layer 0: deterministic obfuscation decoding (0 LLM calls)."""

    name = "normalization"

    def __init__(self) -> None:
        self._normalizer = norm_mod.DeterministicNormalizer()

    async def process(self, exchange: Exchange) -> Exchange:
        original = exchange.content
        exchange.content = self._normalizer.normalize(exchange.content)
        exchange.metadata["normalization"] = {
            "changed": exchange.content != original,
        }
        return exchange


class ThreatClassificationLayer(DefenseLayer):
    """Layer 1: rule-based threat classification with policy blocking."""

    name = "threat_classification"

    DEFAULT_BLOCK_CATEGORIES = ("indirect_injection", "jailbreak", "prompt_extraction")

    def __init__(
        self,
        block_categories: tuple[str, ...] = DEFAULT_BLOCK_CATEGORIES,
        min_confidence: float = 0.4,
    ) -> None:
        self.block_categories = frozenset(block_categories)
        self.min_confidence = min_confidence
        self._classifier = tc_mod.ThreatClassifier()

    async def process(self, exchange: Exchange) -> Exchange:
        result = self._classifier.classify(exchange.content)
        category = result.category.value
        exchange.metadata["threat"] = {
            "category": category,
            "confidence": result.confidence,
            "risk_score": result.flags.risk_score,
            "evidence": result.evidence,
        }
        should_block = (
            category in self.block_categories and result.confidence >= self.min_confidence
        )
        if should_block:
            exchange.block(
                f"threat_classification: {category} "
                f"(confidence={result.confidence:.2f})"
            )
        return exchange


class SegmentationLayer(DefenseLayer):
    """Layer 1.5: trust-boundary segmentation (0 LLM calls)."""

    name = "segmentation"

    def __init__(self, context: dict[str, Any] | None = None) -> None:
        self.context = context or {}
        self._segmenter = seg_mod.InputSegmenter()

    async def process(self, exchange: Exchange) -> Exchange:
        segments = self._segmenter.segment(exchange.content, self.context)
        exchange.metadata["segments"] = [
            {
                "text": s.text,
                "trust_score": s.trust_score,
                "source_type": s.source_type,
                "position": s.position,
            }
            for s in segments
        ]
        exchange.metadata["min_segment_trust"] = min(
            (s.trust_score for s in segments), default=1.0
        )
        return exchange


class SpotlightingLayer(DefenseLayer):
    """Layer 2: Polymorphic Prompt Assembling spotlighting wrap (0 LLM calls).

    Rewrites content deterministically per task_id so adaptive attackers
    cannot learn the wrapper structure across rounds.
    """

    name = "spotlighting"

    def __init__(self, task_id: str = "default-task", conversational: bool = True) -> None:
        self.task_id = task_id
        self.conversational = conversational

    async def process(self, exchange: Exchange) -> Exchange:
        wrapped = pd_mod.layer2_spotlighting_wrap(
            exchange.content, self.task_id, is_conversational=self.conversational
        )
        exchange.metadata["spotlighted_original"] = exchange.content
        exchange.content = wrapped
        return exchange


class ExecutionModeLayer(DefenseLayer):
    """Maps accumulated suspicion to a trust-level execution mode."""

    name = "execution_mode"

    def __init__(self) -> None:
        self._selector = em_mod.ExecutionModeSelector()

    async def process(self, exchange: Exchange) -> Exchange:
        suspicion = float(exchange.metadata.get("suspicion", 0.0))
        mode = self._selector.select(suspicion)
        config = self._selector.get_config(mode)
        exchange.metadata["suspicion"] = suspicion
        exchange.metadata["execution_mode"] = mode.value
        exchange.metadata["mode_config"] = {
            "output_trust": config.output_trust,
            "allow_recommendations": config.allow_recommendations,
            "allow_specific_claims": config.allow_specific_claims,
        }
        return exchange


class OutputGuardrailLayer(DefenseLayer):
    """Post-response guardrails: PII/unsafe-code redaction (0 LLM calls)."""

    name = "output_guardrails"

    def __init__(self, context: dict[str, Any] | None = None) -> None:
        self.context = context or {}
        self._guardrails = og_mod.OutputGuardrails()

    async def process(self, exchange: Exchange) -> Exchange:
        if exchange.response is None:
            return exchange
        result = self._guardrails.sanitize_all(exchange.response, self.context)
        exchange.response = result.sanitized_output
        exchange.metadata["output_guardrails"] = {
            "violations": list(result.violations_found),
            "risk_level": result.risk_level,
            "modified": result.was_modified,
        }
        return exchange
