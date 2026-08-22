"""AgentDojo benchmark corpus loader.

Loads the published AgentDojo v1 injection-task fixtures WITHOUT installing
agentdojo's full LLM stack (openai/anthropic/cohere/langchain). The task-suite
modules only need three symbols from ``agentdojo.agent_pipeline``, none of
which are executed by this offline benchmark:

- ``BasePipelineElement`` (abstract base, never instantiated here)
- ``AbortAgentError`` (exception type)
- ``GroundTruthPipeline`` (runtime pipeline, never run here)

We register lightweight stand-ins in ``sys.modules`` before importing the
suite modules, then extract each injection task's GOAL prompt and difficulty.
"""

from __future__ import annotations

import sys
import types
from dataclasses import dataclass

AGENTDOJO_SRC = "agentdojo/src"


@dataclass(frozen=True)
class AgentDojoTask:
    suite: str          # banking | slack | travel | workspace
    task_id: str        # e.g. InjectionTask0
    goal: str           # the hijack goal AgentDojo expects the agent to execute
    difficulty: str     # easy | medium | hard


def _install_agentdojo_stubs() -> None:
    """Register minimal stand-ins for agentdojo.agent_pipeline."""
    pkg = types.ModuleType("agentdojo.agent_pipeline")
    pkg.__path__ = []  # mark as package so submodule imports hit sys.modules

    class BasePipelineElement:  # pragma: no cover - structural stub
        pass

    class AbortAgentError(Exception):  # pragma: no cover - structural stub
        pass

    class GroundTruthPipeline(BasePipelineElement):  # pragma: no cover
        def __init__(self, task=None) -> None:
            self._task = task

    pkg.BasePipelineElement = BasePipelineElement
    pkg.AbortAgentError = AbortAgentError
    pkg.GroundTruthPipeline = GroundTruthPipeline

    sys.modules.setdefault("agentdojo.agent_pipeline", pkg)
    for name in ("base_pipeline_element", "errors", "ground_truth_pipeline"):
        sub = types.ModuleType(f"agentdojo.agent_pipeline.{name}")
        for attr in ("BasePipelineElement", "AbortAgentError", "GroundTruthPipeline"):
            setattr(sub, attr, getattr(pkg, attr))
        sys.modules.setdefault(f"agentdojo.agent_pipeline.{name}", sub)


def _bypass_default_suites_init() -> None:
    """Register pass-through modules for default_suites packages.

    Their ``__init__`` files eagerly import every suite version (v1_1, v1_2,
    ...), which triggers circular imports under partial initialization. We
    register empty package modules whose ``__path__`` points at the real
    directories, so ``import agentdojo.default_suites.v1.banking`` resolves
    the real files without executing the eager inits.
    """
    import pathlib

    base = pathlib.Path(AGENTDOJO_SRC) / "agentdojo" / "default_suites"
    for name, path in (
        ("agentdojo.default_suites", base),
        ("agentdojo.default_suites.v1", base / "v1"),
        ("agentdojo.task_suite", pathlib.Path(AGENTDOJO_SRC) / "agentdojo" / "task_suite"),
    ):
        if name in sys.modules:
            continue
        mod = types.ModuleType(name)
        mod.__path__ = [str(path)]
        sys.modules[name] = mod


_SUITES = ("banking", "slack", "travel", "workspace")


def load_agentdojo_v1_tasks() -> list[AgentDojoTask]:
    """Load all v1 injection tasks across the four published suites."""
    if AGENTDOJO_SRC not in sys.path:
        sys.path.insert(0, AGENTDOJO_SRC)
    _install_agentdojo_stubs()
    _bypass_default_suites_init()

    tasks: list[AgentDojoTask] = []
    for suite in _SUITES:
        module_name = f"agentdojo.default_suites.v1.{suite}"
        __import__(module_name)
        suite_obj = getattr(sys.modules[module_name], f"{suite}_task_suite")
        for task_id, task in sorted(suite_obj.injection_tasks.items()):
            tasks.append(AgentDojoTask(
                suite=suite,
                task_id=task_id,
                goal=task.GOAL,
                difficulty=getattr(task.DIFFICULTY, "name", str(task.DIFFICULTY)).lower(),
            ))
    return tasks
