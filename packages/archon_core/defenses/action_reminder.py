"""Action-time policy reminder DefenseLayer.

Source: arXiv:2608.10669 (REDAgentBench) -- injecting a case-specific policy
reminder AT THE ACTION BOUNDARY cut confirmed violations by -74.19pp
[CI 69.85-78.41], while static self-reminders only achieved -25..-37pp and a
placebo interjection matched baseline. This layer implements the winning arm:
a runtime interjection appended to the exchange content when a trigger fires,
NOT a system-prompt edit. The exchange is never blocked; the reminder steers
downstream behavior instead.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from ..models import Exchange
from .base import DefenseLayer

__all__ = [
    "SELF_REMINDER_TEXT",
    "ActionReminderLayer",
    "PolicyReminder",
    "replay_with_placebo",
]

REMINDER_MARKER = "[ACTION-TIME POLICY REMINDER]"
REMINDER_TEMPLATE = f"\n{REMINDER_MARKER} {{reminder}}\n"

SELF_REMINDER_TEXT = "Remember all safety constraints."

_PLACEBO_FILLER = (
    "the assistant handled this request under its usual operating routine today "
)


@dataclass
class PolicyReminder:
    """A case-specific constraint keyed on a case-insensitive regex trigger."""

    trigger: str
    reminder: str


def _neutral_text(length: int) -> str:
    """Deterministic character-matched placebo text of exactly ``length`` chars."""
    return (_PLACEBO_FILLER * ((length // len(_PLACEBO_FILLER)) + 1))[:length]


class ActionReminderLayer(DefenseLayer):
    """Appends a case-specific policy reminder at the action boundary (0 LLM calls).

    First matching reminder wins; matching is case-insensitive regex over the
    exchange content. Non-blocking by design -- the interjection text itself is
    the intervention.
    """

    name = "action_reminder"

    def __init__(
        self, reminders: list[PolicyReminder], mode: str = "interject"
    ) -> None:
        if mode != "interject":
            raise ValueError(f"unsupported reminder mode: {mode!r}")
        self.reminders = list(reminders)
        self.mode = mode
        self._compiled = [(re.compile(r.trigger, re.IGNORECASE), r) for r in self.reminders]

    def would_remind(self, content: str) -> PolicyReminder | None:
        """Return the first PolicyReminder whose trigger matches, else None."""
        for pattern, reminder in self._compiled:
            if pattern.search(content):
                return reminder
        return None

    async def process(self, exchange: Exchange) -> Exchange:
        matched = self.would_remind(exchange.content)
        if matched is None:
            return exchange
        exchange.content += REMINDER_TEMPLATE.format(reminder=matched.reminder)
        exchange.metadata["action_reminder"] = {
            "trigger": matched.trigger,
            "reminder": matched.reminder,
            "mode": self.mode,
        }
        return exchange


class _ConstantInterjectionLayer(DefenseLayer):
    """Self-reminder arm: appends the same generic text to every payload."""

    name = "self_reminder"

    def __init__(self, text: str) -> None:
        self.text = text

    async def process(self, exchange: Exchange) -> Exchange:
        exchange.content += REMINDER_TEMPLATE.format(reminder=self.text)
        return exchange


class _PlaceboLayer(DefenseLayer):
    """Placebo arm: character-matched neutral interjection where triggers fire."""

    name = "placebo_reminder"

    def __init__(self, reminders: list[PolicyReminder]) -> None:
        self._policy = ActionReminderLayer(reminders)

    async def process(self, exchange: Exchange) -> Exchange:
        matched = self._policy.would_remind(exchange.content)
        if matched is None:
            return exchange
        exchange.content += REMINDER_TEMPLATE.format(reminder=_neutral_text(len(matched.reminder)))
        return exchange


async def replay_with_placebo(
    pipeline_factory,
    payloads: list[str],
    reminders: list[PolicyReminder],
) -> dict[str, dict[str, int]]:
    """Run matched payloads through three arms and compare outcomes.

    Arms:
      * ``policy``  -- ActionReminderLayer with the given reminders.
      * ``self``    -- generic 'Remember all safety constraints.' on every turn.
      * ``placebo`` -- neutral filler of the same length as the policy reminder.

    ``pipeline_factory(layers)`` must build a DefensePipeline that includes the
    provided pre-layers plus any downstream detector under test. Returns, per
    arm, ``{"reminded_count", "downstream_flagged_count"}`` so callers can
    assert the reminder changes downstream classification deterministically.
    """
    arms: dict[str, DefenseLayer] = {
        "policy": ActionReminderLayer(reminders),
        "self": _ConstantInterjectionLayer(SELF_REMINDER_TEXT),
        "placebo": _PlaceboLayer(reminders),
    }
    results: dict[str, dict[str, int]] = {}
    for arm_name, layer in arms.items():
        reminded = 0
        flagged = 0
        pipeline = pipeline_factory([layer])
        for payload in payloads:
            exchange = await pipeline.run(Exchange(content=payload))
            if REMINDER_MARKER in exchange.content:
                reminded += 1
            if exchange.blocked:
                flagged += 1
        results[arm_name] = {
            "reminded_count": reminded,
            "downstream_flagged_count": flagged,
        }
    return results
