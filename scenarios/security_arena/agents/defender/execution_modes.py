"""Execution mode scaling module.

Based on NeuralShield's architecture: maps suspicion score to 4 execution modes
with varying trust levels and feature availability.

Modes:
  STANDARD   (suspicion < 0.2) — full trust, all features
  CAUTIOUS   (0.2–0.5)         — 0.8 trust, recommendations allowed
  CONSERVATIVE (0.5–0.8)       — 0.5 trust, no recommendations or specific claims
  MINIMAL    (> 0.8)           — 0.2 trust, generic safe responses only
"""

from dataclasses import dataclass
from enum import Enum


class ExecutionMode(Enum):
    """Four execution modes mapped from suspicion scores."""
    STANDARD = "standard"
    CAUTIOUS = "cautious"
    CONSERVATIVE = "conservative"
    MINIMAL = "minimal"


@dataclass
class ModeConfig:
    """Configuration for an execution mode."""
    output_trust: float
    allow_recommendations: bool
    allow_specific_claims: bool
    response_style: str


_MODE_CONFIGS: dict[ExecutionMode, ModeConfig] = {
    ExecutionMode.STANDARD: ModeConfig(
        output_trust=1.0,
        allow_recommendations=True,
        allow_specific_claims=True,
        response_style="standard",
    ),
    ExecutionMode.CAUTIOUS: ModeConfig(
        output_trust=0.8,
        allow_recommendations=True,
        allow_specific_claims=True,
        response_style="cautious",
    ),
    ExecutionMode.CONSERVATIVE: ModeConfig(
        output_trust=0.5,
        allow_recommendations=False,
        allow_specific_claims=False,
        response_style="conservative",
    ),
    ExecutionMode.MINIMAL: ModeConfig(
        output_trust=0.2,
        allow_recommendations=False,
        allow_specific_claims=False,
        response_style="minimal",
    ),
}


class ExecutionModeSelector:
    """Maps a suspicion score (0.0–1.0) to an execution mode."""

    def select(self, suspicion_score: float) -> ExecutionMode:
        """Select execution mode based on suspicion score.

        Thresholds:
            < 0.2  → STANDARD
            0.2–0.5 → CAUTIOUS
            0.5–0.8 → CONSERVATIVE
            > 0.8  → MINIMAL
        """
        if suspicion_score < 0.2:
            return ExecutionMode.STANDARD
        elif suspicion_score < 0.5:
            return ExecutionMode.CAUTIOUS
        elif suspicion_score < 0.8:
            return ExecutionMode.CONSERVATIVE
        else:
            return ExecutionMode.MINIMAL

    def get_config(self, mode: ExecutionMode) -> ModeConfig:
        """Return the configuration for the given execution mode."""
        return _MODE_CONFIGS[mode]
