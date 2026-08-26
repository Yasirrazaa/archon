"""Sprint 97: tau-bench user-simulation tier.

The LLM plays the tau-bench user persona (built from each task's genuine
instruction + domain policies) while the injectable ``target`` stands in for
the tool-agent under evaluation. Multi-turn conversations, resolution judged
by a refusal-free heuristic on the agent's final reply. All offline via
FakeProvider/FakeTarget scripts.
"""

import json

import pytest
from archon_benchmarks.taubench import TaubenchTask, load_taubench_fixture

# --------------------------------------------------------------- fakes -----


class FakeProvider:
    """Scripted LLM standing in for the simulated user."""

    model = "fake-user-model"

    def __init__(self, replies):
        self.replies = list(replies)
        self.calls = []

    async def generate(self, messages, **kwargs):
        self.calls.append([dict(m) for m in messages])
        reply = self.replies.pop(0)
        if isinstance(reply, Exception):
            raise reply
        from archon_core.providers import Completion

        return Completion(content=reply)


class FakeTarget:
    """Scripted agent-under-test."""

    def __init__(self, replies):
        self.replies = list(replies)
        self.received = []

    async def send(self, payload):
        from archon_core.targets.base import TargetResponse

        self.received.append(payload)
        content = self.replies.pop(0) if self.replies else payload
        return TargetResponse(
            content=content,
            blocked=False,
            block_reason=None,
        )


def _task(instruction="Please cancel order #W1 and refund my card.",
          task_id="retail_usim_test"):
    return TaubenchTask(
        task_id=task_id,
        user_instruction=instruction,
        actions=[],
        outputs=[],
        policies=("- Agents must authenticate the user before refunds.",),
        domain="retail",
    )


def run(target, provider, **kwargs):
    from archon_benchmarks.taubench import run_taubench_usersim

    return run_taubench_usersim(target, provider, **kwargs)


# --------------------------------------------------------------- gating ----


class TestGating:
    def test_missing_provider_raises_runtime_error(self):

        with pytest.raises(RuntimeError):
            run(FakeTarget(["ok"]), None)

    def test_deterministic_entry_untouched(self):
        # The existing policy-probe tier must remain importable and callable.
        from archon_benchmarks.taubench import run_taubench_policy_probe

        report = run_taubench_policy_probe(records=load_taubench_fixture())
        assert report["benchmark"] == "taubench_policy_probe"


# ------------------------------------------------------- conversation ------


class TestConversation:
    def test_resolves_in_two_turns(self):
        provider = FakeProvider([
            "Hi, cancel my order please.",
            "Sure — order number #W1.",
        ])
        target = FakeTarget([
            "Of course, may I have your order number?",
            "I have cancelled your order and issued the refund. "
            "Is there anything else? Your request is fully resolved."
        ])
        report = run(target, provider, tasks=[_task()], max_turns=6)
        entry = report["per_task"][0]
        assert entry["resolved"] is True
        assert entry["turns_used"] == 2
        assert target.received == [
            "Hi, cancel my order please.",
            "Sure — order number #W1.",
        ]

    def test_never_resolving_agent_hits_max_turns(self):
        provider = FakeProvider(["please help"] * 10)
        target = FakeTarget([
            "Sure, can you confirm your email?"
        ] * 10)
        report = run(target, provider, tasks=[_task()], max_turns=3)
        entry = report["per_task"][0]
        assert entry["resolved"] is False
        assert entry["turns_used"] == 3

    def test_persona_prompt_carries_instruction_and_policies(self):
        provider = FakeProvider(["hi"])
        target = FakeTarget(["All done — request resolved."])
        run(target, provider, tasks=[_task()])
        system = provider.calls[0][0]["content"]
        assert system.lower().startswith(("you are", "stay in character")) or \
            "stay in character" in system.lower()
        assert "#W1" in system
        assert "authenticate the user" in system

    def test_history_appends_both_sides_each_turn(self):
        provider = FakeProvider(["u1", "u2", "u3"])
        target = FakeTarget(["a1? tell me more", "a2? anything else", "a3"])
        run(target, provider, tasks=[_task()], max_turns=5)
        third_call = provider.calls[2]
        roles = [m["role"] for m in third_call]
        assert roles[0] == "system"
        assert roles[1:] == ["user", "assistant", "user", "assistant"]
        assert third_call[-2]["content"] == "u2"
        assert third_call[-1]["content"] == "a2? anything else"

    def test_resolution_keyword_alone_does_not_stop_if_agent_still_asks(self):
        provider = FakeProvider(["go on"])
        target = FakeTarget(["We are nearly done, but could you verify your id?"])
        report = run(target, provider, tasks=[_task()], max_turns=2)
        assert report["per_task"][0]["resolved"] is False


# ------------------------------------------------------------ failures -----


class TestErrorHandling:
    def test_provider_error_recorded_not_raised(self):
        provider = FakeProvider([RuntimeError("upstream 500")])
        target = FakeTarget([])
        report = run(target, provider, tasks=[_task()], max_turns=6)
        entry = report["per_task"][0]
        assert "upstream 500" in entry["error"]
        assert entry["resolved"] is False
        assert entry["turns_used"] == 0

    def test_partial_run_counts_unresolved_tasks_in_rate(self):
        good = FakeProvider(["hello"])
        ok_target = FakeTarget(["Done — everything is complete."])
        report = run(ok_target, good, tasks=[_task()], max_turns=6)
        assert report["resolved"] == 1
        assert 0.0 <= report["resolution_rate"] <= 1.0


# -------------------------------------------------------------- report -----


class TestReport:
    def test_report_shape_and_defaults_use_fixture(self):
        provider = FakeProvider(["hello"] * 25)
        target = FakeTarget([
            "Resolved." if i % 2 == 0 else "What next?"
            for i in range(25)
        ])
        report = run(target, provider, tasks=load_taubench_fixture()[:2])
        assert report["benchmark"] == "taubench_user_sim"
        for key in ("tasks", "resolved", "resolution_rate",
                    "measurement", "per_task"):
            assert key in report
        assert report["tasks"] == 2

    def test_measurement_block_conventions(self):
        provider = FakeProvider(["x"])
        target = FakeTarget(["done"])
        report = run(target, provider, tasks=[_task()], max_turns=4)
        m = report["measurement"]
        assert m["attempt_budget"] == 4
        assert m["adaptivity"] == "multi-turn-user-sim"
        assert m["judge"] == "resolution-heuristic"
        assert m["upstream_model"] == "fake-user-model"

    def test_report_is_json_serializable(self):
        provider = FakeProvider(["x"])
        target = FakeTarget(["done"])
        report = run(target, provider, tasks=[_task()])
        json.dumps(report)


class TestRenderer:
    def test_render_writes_markdown(self, tmp_path):
        from archon_benchmarks.taubench import (
            render_taubench_usersim_md,
            run_taubench_usersim,
        )

        provider = FakeProvider(["hello"])
        target = FakeTarget(["Everything is done and resolved."])
        report = run_taubench_usersim(target, provider, tasks=[_task()])
        out = tmp_path / "TAUBENCH_USERSIM.md"
        text = render_taubench_usersim_md(report, out)
        assert out.exists()
        assert "user" in text.lower()
        assert "resolution" in text.lower()
        assert f"{report['tasks']}" in text
