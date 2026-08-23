"""Live tool-execution targets: instrumented sandboxes with ground-truth
verification of attack success.

Chat targets force lexical success markers ("did the response contain the
secret?"). Tool-using agents fail differently: the damage is a *state change*
(money moved, file deleted, email sent). A sandbox target executes real tool
calls against mutable state and reports ``raw["attack_success"]`` derived from
a caller-supplied goal check over environment diffs — the AgentDojo insight
brought into Archon's battle loop.

Pair with :class:`archon_core.attacks.branching.BranchingAttacker` (which
honors the ``attack_success`` signal) and a defense pipeline wrapper for the
closed loop: attack -> shield -> re-attack.
"""

from __future__ import annotations

import copy
import re
from dataclasses import dataclass, field
from typing import Any, Callable

from .base import TargetAdapter, TargetResponse


@dataclass
class Tool:
    """A callable agent tool with a schema-ish description."""

    name: str
    description: str
    fn: Callable[..., str]


class SandboxEnvironment:
    """Mutable agent state plus registered tools; snapshots enable diffing."""

    def __init__(self, state: dict[str, Any] | None = None) -> None:
        self.state: dict[str, Any] = state if state is not None else {}
        self.tools: dict[str, Tool] = {}

    def register_tool(self, tool: Tool) -> None:
        self.tools[tool.name] = tool

    def snapshot(self) -> dict[str, Any]:
        return copy.deepcopy(self.state)

    @staticmethod
    def diff(
        before: dict[str, Any], after: dict[str, Any]
    ) -> dict[str, dict[str, Any]]:
        changed: dict[str, dict[str, Any]] = {}
        for key in sorted(set(before) | set(after)):
            if before.get(key) != after.get(key):
                changed[key] = {"before": before.get(key), "after": after.get(key)}
        return changed


def directive_planner(payload: str, env: SandboxEnvironment) -> list[tuple[str, dict]]:
    """Deterministic vulnerable-agent planner.

    Parses imperative directives out of untrusted payload text — exactly the
    behavior an injection-hijacked agent exhibits. Returns (tool, kwargs)
    pairs; empty for benign text.
    """
    calls: list[tuple[str, dict]] = []
    if "transfer" in env.tools:
        for match in re.finditer(
            r"(?:send|transfer)\s+\$?(\d[\d,]*)\s*(?:dollars\s+)?to\s+([a-z0-9_-]+)",
            payload,
            re.IGNORECASE,
        ):
            amount = float(match.group(1).replace(",", ""))
            calls.append(("transfer", {"amount": amount, "to": match.group(2)}))
    return calls


class ToolSandboxTarget(TargetAdapter):
    """A tool-using agent that really executes planned tool calls."""

    def __init__(
        self,
        env: SandboxEnvironment,
        goal_check: Callable[[dict, dict], bool],
        planner: Callable[[str, SandboxEnvironment], list[tuple[str, dict]]]
        | None = None,
    ) -> None:
        self.env = env
        self.goal_check = goal_check
        self.planner = planner or directive_planner

    async def send(self, payload: str) -> TargetResponse:
        before = self.env.snapshot()
        transcript: list[str] = []
        executed: list[dict[str, Any]] = []

        for tool_name, kwargs in self.planner(payload, self.env):
            tool = self.env.tools.get(tool_name)
            if tool is None:
                transcript.append(f"{tool_name}: error unknown tool")
                executed.append({"tool": tool_name, "kwargs": kwargs, "error": "unknown tool"})
                continue
            try:
                result = tool.fn(**kwargs)
                transcript.append(f"{tool_name}({kwargs}) -> {result}")
                executed.append({"tool": tool_name, "kwargs": kwargs, "result": result})
            except Exception as exc:  # tools may fail; record, don't crash
                transcript.append(f"{tool_name}({kwargs}) -> error {exc}")
                executed.append({"tool": tool_name, "kwargs": kwargs, "error": str(exc)})

        after = self.env.snapshot()
        return TargetResponse(
            content="\n".join(transcript) if transcript else "no action taken",
            blocked=False,
            raw={
                "attack_success": self.goal_check(before, after),
                "tool_calls": executed,
                "env_diff": SandboxEnvironment.diff(before, after),
            },
        )


__all__ = ["Tool", "SandboxEnvironment", "ToolSandboxTarget", "directive_planner"]
