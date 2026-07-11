"""Archon: Adversarial Agent Security Framework.

A multi-turn adversarial agent-security testing framework built for the
Lambda x Berkeley RDI AgentBeats Security Arena competition.

Archon placed 13th overall, 6th Defense (85.1% win rate), 18th Attack (14.4% win rate)
on the private leaderboard with 49.7% average win rate.

Key components:
- A2A protocol-based agent orchestration
- GOAT-loop adaptive attacker with 7-round persistent state
- 4-layer defense pipeline with constitutional task shield
- 5 scenario plugins (PortfolioIQ, Thingularity, GymJailbreak, ResumeDowngrade, Medical)
- Normal-user helpfulness gate for leaderboard eligibility
"""

__version__ = "0.1.0"
__author__ = "Archon Team"
__license__ = "MIT"

from archon.client import send_message
from archon.config import Settings, get_settings, reset_settings
from archon.green_executor import GreenAgent, GreenExecutor
from archon.models import EvalRequest, EvalResult
from archon.tool_provider import ToolProvider

__all__ = [
    "EvalRequest",
    "EvalResult",
    "GreenAgent",
    "GreenExecutor",
    "ToolProvider",
    "send_message",
    "Settings",
    "get_settings",
    "reset_settings",
]
