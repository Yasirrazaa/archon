"""Multi-provider benchmark matrix runner (SPRINT 96).

Runs the same live suite(s) across several providers and assembles a
comparison matrix of per-(provider, suite) report summaries.

Each cell runs one ``archon_benchmarks.live_runner`` phase function with a
freshly built cfg (mirrors :func:`live_runner.resolve_config`, but the API
key comes from the provider's own env var). Cell failures are recorded in
the matrix instead of aborting the run — one broken provider must never
kill the whole sweep.

Usage::

    from archon_benchmarks.matrix_runner import run_matrix

    result = run_matrix(
        [
            {"name": "prov-a", "base_url": "https://a.test/v1",
             "model": "m-a", "api_key_env": "PROV_A_KEY"},
            {"name": "prov-b", "base_url": "https://b.test/v1",
             "model": "m-b", "api_key_env": "PROV_B_KEY"},
        ],
        suites=["strongreject", "agentharm"],
    )
    print(result["markdown"])

Reports land under ``<out_dir>/<provider_name>/<suite>.json`` via
``live_runner.save_report`` so partial progress survives crashes.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Callable

# Key metric extracted from each suite's report (first present wins).
METRICS_BY_SUITE: dict[str, tuple[str, ...]] = {
    "strongreject": ("mean_strongreject_score",),
    "agentharm": ("compliance_rate", "refusal_rate"),
}

DEFAULT_SUITES = ["strongreject", "agentharm"]
DEFAULT_OUT_DIR = "live_results/matrix"

RunnerFn = Callable[[str, dict[str, str], Path, int], dict[str, Any]]


def _default_runner(
    suite: str, cfg: dict[str, str], out_dir: Path, concurrency: int
) -> dict[str, Any]:
    """Bridge to the live_runner PHASES registry."""
    from archon_benchmarks import live_runner

    return live_runner.PHASES[suite](
        out_dir, cfg, concurrency=concurrency
    )


def _build_cfg(provider: dict[str, str]) -> dict[str, str]:
    """Build a live_runner-style cfg for one provider entry.

    Mirrors ``resolve_config``'s shape ({base_url, api_key, model}) but the
    key is read from the provider's dedicated env var.
    """
    api_key = os.environ.get(provider["api_key_env"], "")
    if not api_key:
        raise RuntimeError(
            f"API key env var {provider['api_key_env']!r} not set "
            f"(provider {provider['name']!r})"
        )
    return {
        "base_url": provider["base_url"],
        "api_key": api_key,
        "model": provider["model"],
    }


def _extract_metric(suite: str, report: dict[str, Any]) -> tuple[str, Any]:
    """Pick the suite's key metric out of its report."""
    for name in METRICS_BY_SUITE.get(suite, ()):
        if name in report:
            return name, report[name]
    return "unknown", None


def render_matrix_md(rows: list[dict[str, Any]]) -> str:
    """Render matrix rows as a markdown comparison table."""
    lines = [
        "| Provider | Model | Suite | Metric | Value | Error |",
        "|---|---|---|---|---|---|",
    ]
    for row in rows:
        value = row["value"]
        value = f"{value}" if value is not None else "-"
        error = row.get("error") or ""
        lines.append(
            f"| {row['provider']} | {row['model']} | {row['suite']} "
            f"| {row['metric_name']} | {value} | {error} |"
        )
    return "\n".join(lines)


def run_matrix(
    providers: list[dict[str, str]],
    suites: list[str] | None = None,
    concurrency: int = 4,
    out_dir: str = DEFAULT_OUT_DIR,
    runner_fn: RunnerFn | None = None,
) -> dict[str, Any]:
    """Run ``suites`` across every provider; return the comparison matrix.

    Errors per cell are caught and recorded (``error`` key, ``value=None``)
    — never raised — so one failing provider/suite cannot abort the sweep.
    """
    suites = list(suites) if suites is not None else list(DEFAULT_SUITES)
    runner = runner_fn if runner_fn is not None else _default_runner
    base_out = Path(out_dir)

    matrix: list[dict[str, Any]] = []
    for provider in providers:
        try:
            cfg = _build_cfg(provider)
        except RuntimeError as exc:
            for suite in suites:
                matrix.append(
                    {
                        "provider": provider["name"],
                        "model": provider["model"],
                        "suite": suite,
                        "metric_name": "unknown",
                        "value": None,
                        "error": str(exc),
                    }
                )
            continue

        provider_out = base_out / provider["name"]
        for suite in suites:
            cell: dict[str, Any] = {
                "provider": provider["name"],
                "model": provider["model"],
                "suite": suite,
                "metric_name": "unknown",
                "value": None,
            }
            try:
                report = runner(suite, cfg, provider_out, concurrency)
                metric_name, value = _extract_metric(suite, report or {})
                cell["metric_name"] = metric_name
                cell["value"] = value
            except Exception as exc:  # noqa: BLE001 - record, don't raise
                cell["error"] = f"{type(exc).__name__}: {exc}"
            matrix.append(cell)

    return {"matrix": matrix, "markdown": render_matrix_md(matrix)}
