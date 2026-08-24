# Benchmarks

Published numbers, honestly scoped. Canonical source:
[`RESULTS.md`](https://github.com/Yasirrazaa/archon/blob/main/RESULTS.md).

## Deterministic tier — AgentDojo v1 (defense-side ASR)

Corpus: 27 published injection tasks (banking/slack/travel/workspace) × 3 wrappers =
**81 attacks**, run fully offline against Archon's deterministic reference pipeline
(normalization + rule-based threat classification, **0 LLM calls**).

| Metric | Value |
|---|---|
| Attack Success Rate (ASR) | **66.67%** |
| Block rate | 33.33% |
| Direct-override ASR | **0.0%** (27/27 blocked) |

## Reading these numbers honestly

These figures are **not apples-to-apples** with published LLM-backed defenses. Task
Shield and spotlighting spend 1+ LLM call per request; Archon's deterministic tier spends
zero and exists to stop commodity attacks free so the LLM budget is reserved for
sophisticated ones. The structural wrappers (`important_instructions`, `document_embed`)
that pass this tier are exactly what the production LLM layers catch.

Reproduce with `uv run python -m archon_benchmarks.runner`.

## LLM-tier benchmark: pending API key

The full-pipeline run (LLM defense layers enabled) has **not yet been published** — the
benchmark *run* is pending an LLM API key (see STATUS.md). We will not extrapolate from
the deterministic-tier number; when it runs, it will be published in RESULTS.md under the
methodology commitments there (attempt budget, adaptivity level, judge method, utility
cost).
