"""Reproducible live-LLM benchmark runner — repo-resident driver for all
LLM-dependent benchmark phases.

Phases (each builds FRESH provider/target inside its own event loop; never
share httpx clients across ``asyncio.run`` boundaries):

- ``strongreject``: rubric-judge live run (~313 upstream calls + judge calls)
- ``agentharm``: live behaviors w/ refusal-heuristic judge (~176-350 calls)
- ``rjudge``: LLM-judged safety agreement over 571 records
- ``piminer``: PiminerBrainAttacker @ budget 25 vs the reference-pipeline
  shield over AgentDojo v1 (the decisive head-to-head only Archon can run);
  resumes from ``piminer_vs_shield_partial.json``

Usage::

    python -m archon_benchmarks.live_runner --phases strongreject rjudge \
        --out live_results

Env:
    OPENROUTER_API_KEY or ARCHON_ATTACK_PROVIDER_API_KEY  (required)
    ARCHON_LLM_BENCH_BASE_URL   (default https://openrouter.ai/api/v1)
    ARCHON_LLM_BENCH_MODEL      (default stealth/ox-alpha)

Results are written incrementally as JSON into ``--out`` so partial progress
survives crashes and quota exhaustion.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import time
from pathlib import Path
from typing import Any, Callable

import httpx
from dotenv import load_dotenv

_REPO = Path(__file__).resolve().parents[2]

DEFAULT_BASE_URL = "https://openrouter.ai/api/v1"
DEFAULT_MODEL = "stealth/ox-alpha"


# ---------------------------------------------------------------------------
# Sync completion shim (strongreject's rubric judge calls provider.complete()
# synchronously inside a running loop — async providers can't be bridged).
# ---------------------------------------------------------------------------


class CompleteShim:
    """Synchronous ``.complete(prompt) -> str`` over /chat/completions.

    Retries 429/5xx with exponential backoff; never retries other 4xx.
    """

    def __init__(
        self,
        base_url: str,
        api_key: str | None,
        model: str,
        timeout_seconds: float = 120.0,
        transport: httpx.BaseTransport | None = None,
        max_retries: int = 5,
        backoff_seconds: float = 4.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.max_retries = max_retries
        self.backoff_seconds = backoff_seconds
        self._client = httpx.Client(
            timeout=timeout_seconds, transport=transport
        )

    def complete(self, prompt: str) -> str:
        headers = {"Content-Type": "application/json"}
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        body = {
            "model": self.model,
            "messages": [{"role": "user", "content": prompt}],
        }
        attempt = 0
        while True:
            resp = self._client.post(
                f"{self.base_url}/chat/completions",
                json=body,
                headers=headers,
            )
            if resp.status_code == 200:
                data = resp.json()
                return data["choices"][0]["message"]["content"]
            if resp.status_code == 429 or resp.status_code >= 500:
                if attempt >= self.max_retries:
                    raise RuntimeError(
                        f"upstream exhausted after {attempt + 1} attempts "
                        f"(last status {resp.status_code})"
                    )
                sleep_s = self.backoff_seconds * (2**attempt)
                print(f"[judge-retry] {resp.status_code}; sleep {sleep_s:.0f}s")
                time.sleep(sleep_s)
                attempt += 1
                continue
            raise RuntimeError(
                f"upstream client error {resp.status_code}: {resp.text[:200]}"
            )


# ---------------------------------------------------------------------------
# Config resolution
# ---------------------------------------------------------------------------


def resolve_config(
    base_url: str | None = None,
    model: str | None = None,
    env_file: Path | None = _REPO / ".env",
) -> dict[str, str]:
    """Resolve API key / base URL / model from env (+ explicit overrides)."""
    if env_file is not None:
        load_dotenv(env_file)  # explicit path: find_dotenv walks from script dir
    api_key = os.environ.get("OPENROUTER_API_KEY") or os.environ.get(
        "ARCHON_ATTACK_PROVIDER_API_KEY"
    )
    if not api_key:
        raise RuntimeError(
            "API key required: set OPENROUTER_API_KEY or "
            "ARCHON_ATTACK_PROVIDER_API_KEY"
        )
    return {
        "api_key": api_key,
        "base_url": base_url
        or os.environ.get("ARCHON_LLM_BENCH_BASE_URL", DEFAULT_BASE_URL),
        "model": model or os.environ.get("ARCHON_LLM_BENCH_MODEL", DEFAULT_MODEL),
    }


# ---------------------------------------------------------------------------
# Incremental persistence helpers
# ---------------------------------------------------------------------------


def save_report(out_dir: Path, phase: str, report: dict[str, Any]) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{phase}.json"
    path.write_text(json.dumps(report, indent=2))
    return path


def _partial_path(out_dir: Path) -> Path:
    return out_dir / "piminer_vs_shield_partial.json"


def load_piminer_state(out_dir: Path) -> dict[str, Any] | None:
    path = _partial_path(out_dir)
    if not path.exists():
        return None
    return json.loads(path.read_text())


def save_piminer_partial(
    out_dir: Path, completed: list[str], results: list[dict[str, Any]]
) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    payload = {"completed": completed, "results": results}
    _partial_path(out_dir).write_text(json.dumps(payload, indent=2))
    return _partial_path(out_dir)


# ---------------------------------------------------------------------------
# Fresh client factories (never share across asyncio.run loops)
# ---------------------------------------------------------------------------


class _RetryTransport(httpx.AsyncBaseTransport):
    """Retry 429/5xx with exponential backoff (proven pattern from the
    ox-alpha study driver)."""

    def __init__(
        self,
        max_retries: int = 6,
        backoff_seconds: float = 5.0,
        sleeper: Callable[[float], None] = time.sleep,
    ):
        self._inner = httpx.AsyncHTTPTransport()
        self.max_retries = max_retries
        self.backoff_seconds = backoff_seconds
        self._sleep = sleeper

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        attempt = 0
        while True:
            response = await self._inner.handle_async_request(request)
            if response.status_code < 500 and response.status_code != 429:
                return response
            if attempt >= self.max_retries:
                return response
            stream = getattr(response, "stream", None)
            if stream is not None:
                try:
                    await response.aread()
                except Exception:  # pragma: no cover - best effort cleanup
                    pass
            delay = self.backoff_seconds * (2**attempt)
            print(f"[retry] status {response.status_code}; sleep {delay:.0f}s")
            self._sleep(delay)
            attempt += 1


def _make_target(cfg: dict[str, str]):
    from archon_core.targets.openai_compat import OpenAICompatTarget

    return OpenAICompatTarget(
        base_url=cfg["base_url"],
        api_key=cfg["api_key"],
        model=cfg["model"],
        timeout_seconds=300.0,
        transport=_RetryTransport(),
    )


def _make_provider(cfg: dict[str, str]):
    from archon_core.providers.openai_compat import OpenAICompatProvider

    return OpenAICompatProvider(
        base_url=cfg["base_url"],
        api_key=cfg["api_key"],
        model=cfg["model"],
        timeout_seconds=300.0,
        transport=_RetryTransport(),
        max_retries=6,
        backoff_seconds=5.0,
    )


# ---------------------------------------------------------------------------
# Phases
# ---------------------------------------------------------------------------


def run_phase_strongreject(out_dir: Path, cfg: dict[str, str], concurrency: int = 1) -> dict[str, Any]:
    """Rubric-judge live StrongREJECT (~313 target calls + judge calls)."""
    from archon_benchmarks.strongreject import run_strongreject_live

    target = _make_target(cfg)
    judge_provider = CompleteShim(
        base_url=cfg["base_url"],
        api_key=cfg["api_key"],
        model=cfg["model"],
    )
    report = run_strongreject_live(target=target, provider=judge_provider,
                                   concurrency=concurrency)
    save_report(out_dir, "strongreject", report)
    return report


def run_phase_agentharm(out_dir: Path, cfg: dict[str, str], concurrency: int = 1) -> dict[str, Any]:
    """Live AgentHarm behaviors w/ refusal-heuristic judge."""
    from archon_benchmarks.agentharm import run_agentharm_live

    target = _make_target(cfg)
    os.environ["ARCHON_ATTACK_PROVIDER_API_KEY"] = cfg["api_key"]
    report = run_agentharm_live(target=target, concurrency=concurrency)
    save_report(out_dir, "agentharm", report)
    return report


def run_phase_rjudge(out_dir: Path, cfg: dict[str, str], concurrency: int = 1) -> dict[str, Any]:
    """LLM-judged R-Judge agreement over the full 571-record corpus."""
    from archon_benchmarks.rjudge import make_llm_judge, run_rjudge_benchmark

    provider = _make_provider(cfg)
    judge = make_llm_judge(provider)
    report = asyncio.run(run_rjudge_benchmark(judge=judge, concurrency=concurrency))
    save_report(out_dir, "rjudge", report)
    return report


def run_phase_piminer(out_dir: Path, cfg: dict[str, str], concurrency: int = 5) -> dict[str, Any]:
    """PiminerBrainAttacker @ budget 25 vs reference-pipeline shield on
    AgentDojo v1 — resumable per task; hierarchical RunMemory accumulates
    across tasks (cold-start strategy library is the honest config)."""
    from archon_core.attacks.piminer import (
        PiminerBrainAttacker,
        RunMemory,
    )

    from archon_benchmarks.agentdojo_corpus import load_agentdojo_v1_tasks
    from archon_benchmarks.strict_asr import LiveAttackTarget

    tasks = load_agentdojo_v1_tasks()
    state = load_piminer_state(out_dir) or {"completed": [], "results": []}
    done = set(state["completed"])
    results: list[dict[str, Any]] = list(state["results"])
    run_memory = RunMemory()

    pending = [t for t in tasks if t.task_id not in done]
    lock = asyncio.Lock()

    async def _pool() -> None:
        sem = asyncio.Semaphore(max(1, concurrency))

        async def worker(task) -> None:
            async with sem:
                attacker = PiminerBrainAttacker(
                    _make_provider(cfg),
                    max_turns=25,
                    run_memory=run_memory,
                )
                target = LiveAttackTarget(upstream=_make_target(cfg))
                result = await attacker.run(target, task.goal)
                success = bool(
                    getattr(result, "success", getattr(result, "succeeded", False))
                )
                async with lock:
                    results.append(
                        {
                            "task_id": task.task_id,
                            "goal": task.goal,
                            "success": success,
                            "turns_used": getattr(result, "turns_used", None),
                            "errors": len(getattr(result, "errors", []) or []),
                        }
                    )
                    done.add(task.task_id)
                    save_piminer_partial(out_dir, sorted(done), results)
                print(f"[piminer] {task.task_id}: success={success}", flush=True)

        await asyncio.gather(*(worker(t) for t in pending))

    if pending:
        asyncio.run(_pool())

    succeeded = sum(1 for r in results if r["success"])
    report = {
        "benchmark": "piminer_vs_shield",
        "budget_declared": 25,
        "tasks": len(results),
        "succeeded": succeeded,
        "strict_asr": round(succeeded / len(results), 4) if results else None,
        "results": results,
        "measurement": {
            "attempt_budget": 25,
            "adaptivity": "adaptive-hierarchical-memory",
            "judge": "compliance-heuristic+state-guard",
            "upstream_model": cfg["model"],
            "strategy_library": "cold-start (no seeded strategies)",
        },
    }
    save_report(out_dir, "piminer_vs_shield", report)
    return report


PHASES: dict[str, Callable[[Path, dict[str, str]], dict[str, Any]]] = {
    "strongreject": run_phase_strongreject,
    "agentharm": run_phase_agentharm,
    "rjudge": run_phase_rjudge,
    "piminer": run_phase_piminer,
}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="archon_benchmarks.live_runner",
        description="Run all LLM-dependent benchmark phases (reproducible).",
    )
    parser.add_argument(
        "--phases",
        nargs="+",
        default=["strongreject", "agentharm", "rjudge", "piminer"],
        choices=sorted(PHASES),
    )
    parser.add_argument("--out", default="live_results")
    parser.add_argument("--model", default=None)
    parser.add_argument("--concurrency", type=int, default=5,
                        help="Max concurrent in-flight requests (piminer: parallel tasks)")
    parser.add_argument("--base-url", default=None)
    args = parser.parse_args(argv)

    cfg = resolve_config(base_url=args.base_url, model=args.model)
    out_dir = Path(args.out)
    print(
        f"[live-runner] phases={args.phases} model={cfg['model']} "
        f"base_url={cfg['base_url']} out={out_dir}"
    )

    failures: list[str] = []
    for phase in args.phases:
        print(f"[live-runner] === phase: {phase} ===")
        try:
            PHASES[phase](out_dir, cfg, concurrency=args.concurrency)
        except Exception as exc:  # noqa: BLE001 - driver must keep going
            print(f"[live-runner] phase {phase} FAILED: {exc}")
            failures.append(phase)

    if failures:
        print(f"[live-runner] completed with failures: {failures}")
        return 1
    print("[live-runner] all phases complete")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
