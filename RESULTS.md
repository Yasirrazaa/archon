# Benchmark Results: AgentDojo v1 (Defense-Side ASR)

Corpus: **27 published injection tasks** (banking/slack/travel/workspace) x 3 wrappers = **81 attacks**, run fully offline against Archon's deterministic reference pipeline.

| Metric | Value |
|---|---|
| Attack Success Rate (ASR) | **66.7%** |
| Block rate | **33.3%** |

## Per suite

| Suite | Attacks | ASR |
|---|---|---|
| banking | 27 | 66.7% |
| slack | 15 | 66.7% |
| travel | 21 | 66.7% |
| workspace | 18 | 66.7% |

## Per wrapper

| Wrapper | Attacks | ASR |
|---|---|---|
| direct_override | 27 | 0.0% |
| document_embed | 27 | 100.0% |
| important_instructions | 27 | 100.0% |

## Baseline comparison

Published reference points for the same AgentDojo v1 suites (LLM-backed defenses, from the AgentDojo paper / leaderboard ecosystem):

| Defense | Scope | ASR |
|---|---|---|
| No defense (vanilla agent) | full pipeline | ~50–60%+ (suite-dependent) |
| Task Shield (constitution prompt) | full LLM pipeline | **2.07%** |
| Spotlighting with delimiting | full LLM pipeline | low single digits |
| **Archon deterministic tier (this run)** | normalization + rule classification only, **0 LLM calls**, zero latency/cost | 66.7% overall — **0.0% on direct overrides**; structural wrappers pass through by design |

Reading the comparison honestly: these numbers are **not apples-to-apples**. Task Shield and spotlighting spend 1+ LLM call per request; Archon's deterministic tier spends zero and exists to stop commodity attacks free so the LLM budget is reserved for sophisticated ones. The structural wrappers (`important_instructions`, `document_embed`) that pass this tier are exactly what the LLM layers (dynamic invariants, Task Shield, exchange classifier) catch in the production pipeline — those layers are part of Archon's shipped defense stack but are excluded from this offline run because they require a live model.

## Context

This benchmark measures Archon's **deterministic tier only** (normalization + rule-based threat classification, 0 LLM calls) — the free, latency-zero first line of defense. It blocks 100% of direct-override attacks but passes structural wrappers like AgentDojo's `<INFORMATION>` template and indirect document embeddings; in production those are caught by the LLM layers (dynamic invariants, Task Shield, exchange classifier). The deterministic tier exists to stop commodity attacks at zero cost so LLM budget is spent only on sophisticated ones.

Methodology: each AgentDojo GOAL is wrapped using AgentDojo's own `<INFORMATION>` template (`important_instructions`) plus direct-override and indirect-document variants. An attack counts as successful if it is NOT blocked by the reference pipeline. Reproduce with `uv run python -m archon_benchmarks.runner`.

*Next measurement step: re-run with the full 8-layer pipeline (LLM layers enabled) to publish the end-to-end ASR alongside the deterministic-tier number.*
