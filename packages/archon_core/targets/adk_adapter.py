"""Google ADK adapter: battle-target bridge for the Google Agent Framework.

Wraps any ADK Runner/agent exposing one of ``run_async`` (async), ``run``
(sync), or ``query`` (sync) — or a plain callable — behind Archon's
:class:`~archon_core.targets.base.TargetAdapter` contract, so ADK agents can
be probed via :class:`~archon_core.attacks.branching.BranchingAttacker` and
the BattleManager like any other target.

google-adk is an optional dependency ('competition' extra): this module
imports it lazily and works without it for duck-typed runners, while still
accepting real ADK agent objects when the library is installed.
"""

from __future__ import annotations

from typing import Any

from .base import TargetAdapter, TargetResponse


def _load_adk():
    """Return the google.adk module if installed, else None."""
    try:
        import google.adk  # noqa: PLC0415

        return google.adk
    except ImportError:
        return None


def _extract_text(result: Any) -> str:
    """Coerce a runner result to response text (.content first, then str())."""
    content = getattr(result, "content", None)
    if content is not None:
        return str(content)
    return str(result)


class AdkRunnerTarget(TargetAdapter):
    """Target adapter over any duck-typed ADK Runner/agent.

    Invocation order: async ``run_async``, sync ``run``, sync ``query``,
    then plain-callable. Runner exceptions are captured into the response
    (never raised) so one flaky agent cannot kill a battle sweep.
    """

    def __init__(self, runner: Any) -> None:
        self.runner = runner

    async def send(self, payload: str) -> TargetResponse:
        raw = {"adk_adapter": True, "runner_type": type(self.runner).__name__}
        try:
            run_async = getattr(self.runner, "run_async", None)
            if callable(run_async):
                result = await run_async(payload)
            elif callable(getattr(self.runner, "run", None)):
                result = self.runner.run(payload)
            elif callable(getattr(self.runner, "query", None)):
                result = self.runner.query(payload)
            elif callable(self.runner):
                result = self.runner(payload)
            else:
                raise TypeError("runner exposes no invokable method")
            return TargetResponse(
                content=_extract_text(result), blocked=False, raw=raw
            )
        except Exception as exc:
            return TargetResponse(
                content=f"agent error: {exc}",
                blocked=False,
                raw={**raw, "error": str(exc)},
            )


def adk_target_from_agent(agent: Any) -> AdkRunnerTarget:
    """Wrap an object that looks like an ADK agent/runner as a battle target.

    Accepts objects with a ``name`` attribute plus at least one
    runner-invokable method (``run_async``/``run``/``query``) — real ADK
    agents when google-adk is installed, duck types otherwise.
    """
    invokable = (
        callable(getattr(agent, "run_async", None))
        or callable(getattr(agent, "run", None))
        or callable(getattr(agent, "query", None))
    )
    if not (hasattr(agent, "name") and invokable):
        raise TypeError("object does not look like an ADK agent or runner")
    return AdkRunnerTarget(agent)


__all__ = ["AdkRunnerTarget", "_load_adk", "adk_target_from_agent"]
