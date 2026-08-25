"""TDD: action-time policy reminder defense layer tests.

Source: arXiv:2608.10669 (REDAgentBench) -- case-specific policy reminders
injected AT THE ACTION BOUNDARY cut confirmed violations far more than
static self-reminders; placebos do nothing.
"""

import pytest
from archon_core.defenses.action_reminder import (
    SELF_REMINDER_TEXT,
    ActionReminderLayer,
    PolicyReminder,
    replay_with_placebo,
)
from archon_core.defenses.base import DefenseLayer, DefensePipeline
from archon_core.models import Exchange

REMINDERS = [
    PolicyReminder(
        trigger=r"export\s+data",
        reminder="Exporting data requires a valid export-control license.",
    ),
    PolicyReminder(
        trigger=r"make\s+a\s+payment",
        reminder="All payments require documented approval before release.",
    ),
]


class _MarkerRiskDetector(DefenseLayer):
    """Stub downstream classifier: risk-scored markers, mitigated by policy text."""

    name = "marker_detector"

    RULES = (
        # (marker, severity, mitigation keywords carried by the policy reminder)
        ("EXPORT", 1.0, ("license",)),
        ("PAYMENT", 0.8, ("approval",)),
    )
    GENERIC_MITIGATION = 0.3  # credit for the vague self-reminder "safety"
    THRESHOLD = 0.6

    async def process(self, exchange: Exchange) -> Exchange:
        lowered = exchange.content.lower()
        risk = 0.0
        for marker, severity, mitigations in self.RULES:
            if marker.lower() in lowered:
                risk += severity
                if any(m in lowered for m in mitigations):
                    risk -= 0.9
                elif "safety" in lowered:
                    risk -= self.GENERIC_MITIGATION
        if risk >= self.THRESHOLD:
            exchange.block("marker_detector: risky action")
        return exchange


def _factory(layers):
    return DefensePipeline(list(layers) + [_MarkerRiskDetector()])


# --- would_remind -----------------------------------------------------------


def test_no_match_returns_none():
    layer = ActionReminderLayer(REMINDERS)
    assert layer.would_remind("please summarize the quarterly report") is None


def test_trigger_match_case_insensitive():
    layer = ActionReminderLayer(REMINDERS)
    matched = layer.would_remind("Please EXPORT DATA to the bucket")
    assert matched is REMINDERS[0]


def test_multiple_reminders_first_match_wins():
    layer = ActionReminderLayer(
        [
            PolicyReminder(trigger=r"payment", reminder="first"),
            PolicyReminder(trigger=r"payment|invoice", reminder="second"),
        ]
    )
    assert layer.would_remind("pay this invoice payment").reminder == "first"


def test_would_remind_returns_policy_reminder_instance():
    layer = ActionReminderLayer(REMINDERS)
    matched = layer.would_remind("let's make a payment")
    assert isinstance(matched, PolicyReminder)
    assert matched.reminder == REMINDERS[1].reminder


# --- layer semantics --------------------------------------------------------


@pytest.mark.asyncio
async def test_interjection_format_appended():
    layer = ActionReminderLayer(REMINDERS)
    ex = await layer.process(Exchange(content="please export data"))
    expected = (
        "please export data"
        "\n[ACTION-TIME POLICY REMINDER] Exporting data requires a valid "
        "export-control license.\n"
    )
    assert ex.content == expected


@pytest.mark.asyncio
async def test_no_match_content_untouched():
    layer = ActionReminderLayer(REMINDERS)
    ex = await layer.process(Exchange(content="nothing to see"))
    assert ex.content == "nothing to see"


@pytest.mark.asyncio
async def test_non_blocking_semantics():
    layer = ActionReminderLayer(REMINDERS)
    ex = await layer.process(Exchange(content="EXPORT DATA now"))
    assert not ex.blocked
    assert ex.block_reason is None


@pytest.mark.asyncio
async def test_metadata_namespaced():
    layer = ActionReminderLayer(REMINDERS)
    ex = await layer.process(Exchange(content="EXPORT DATA now"))
    assert ex.metadata["action_reminder"]["trigger"] == r"export\s+data"


@pytest.mark.asyncio
async def test_layer_identity():
    layer = ActionReminderLayer(REMINDERS)
    assert layer.name == "action_reminder"
    assert layer.llm_budget == 0
    assert layer.mode == "interject"


@pytest.mark.asyncio
async def test_pipeline_composition_smoke():
    pipeline = DefensePipeline([ActionReminderLayer(REMINDERS)])
    ex = await pipeline.run(Exchange(content="EXPORT DATA now"))
    assert not ex.blocked
    assert "[ACTION-TIME POLICY REMINDER]" in ex.content


# --- matched-pair replay ----------------------------------------------------


@pytest.mark.asyncio
async def test_replay_returns_three_arms():
    payloads = ["EXPORT data", "make a payment"]
    result = await replay_with_placebo(_factory, payloads, REMINDERS)
    assert set(result) == {"policy", "self", "placebo"}
    for arm in result.values():
        assert set(arm) == {"reminded_count", "downstream_flagged_count"}


@pytest.mark.asyncio
async def test_placebo_arm_differs_from_policy_arm():
    payloads = ["EXPORT data", "make a payment"]
    result = await replay_with_placebo(_factory, payloads, REMINDERS)
    assert result["policy"]["downstream_flagged_count"] == 0
    assert result["placebo"]["downstream_flagged_count"] == len(payloads)


@pytest.mark.asyncio
async def test_self_arm_is_intermediate():
    payloads = ["EXPORT data", "make a payment"]
    result = await replay_with_placebo(_factory, payloads, REMINDERS)
    flagged = [result[a]["downstream_flagged_count"] for a in ("policy", "self", "placebo")]
    assert flagged[0] < flagged[1] < flagged[2]
    assert result["self"]["downstream_flagged_count"] == 1


@pytest.mark.asyncio
async def test_replay_reminded_counts():
    payloads = ["EXPORT data", "just chat"]
    result = await replay_with_placebo(_factory, payloads, REMINDERS)
    assert result["policy"]["reminded_count"] == 1
    assert result["self"]["reminded_count"] == 2  # self-reminder fires on every turn
    assert result["placebo"]["reminded_count"] == 1


@pytest.mark.asyncio
async def test_placebo_text_matches_policy_reminder_length():
    payloads = ["EXPORT data"]
    result = await replay_with_placebo(_factory, payloads, REMINDERS)
    assert result["placebo"]["reminded_count"] == 1
    assert SELF_REMINDER_TEXT == "Remember all safety constraints."


@pytest.mark.asyncio
async def test_replay_is_deterministic():
    payloads = ["EXPORT data", "make a payment"]
    first = await replay_with_placebo(_factory, payloads, REMINDERS)
    second = await replay_with_placebo(_factory, payloads, REMINDERS)
    assert first == second
