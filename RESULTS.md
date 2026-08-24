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

## Beyond this benchmark

Since this run was published, Archon's attack surface expanded well beyond HTTP-level probes (post-hackathon sprints, Aug 23): live tool-execution battles with environment-state ground truth (`archon_core.targets.sandbox`), real vector-memory-store poisoning with remediation verification (`archon_core.targets.memory`), ASI07 multi-agent trust-boundary attacks (`archon_core.targets.multiagent`), and trace-driven attack generation from OTel spans (`archon_core.attacks.trace_driven`). These targets report ground-truth `attack_success` from state diffs rather than lexical markers — a follow-up benchmark series will publish ASR for each against the reference pipeline.

## Methodology commitments

Per the NIST CAISI finding that aggregate ASR climbs 57%→80% at 25 attempts per task (and Best-of-N follows a power law), all future published Archon benchmark numbers will state: (1) attempt budget and per-task attempt distribution; (2) adaptivity level of the attacker (static template / branching / LLM-adaptive); (3) judge method and calibration; (4) utility cost of defenses (over-refusal measured via the harmless_helpfulness canary pack); (5) dual ASR where applicable (intermediate vs end-to-end). See `docs/LANDSCAPE_2026.md` §4.3 for the full metrics program (GUARDEDJOINT-style KPIs, Unsafe Action Rate for CI gates, Privilege Escalation Distance on customer tool graphs).

## Multi-attempt series (deterministic tier) — Aug 24, 2026

First published run of the CAISI-methodology multi-attempt benchmark (`archon_benchmarks.multi_attempt`): one adaptive campaign per AgentDojo task, 5-variant mutation rotation (verbatim / paraphrase-prefix / encoding-wrap / role-framing / fragmentation), **attempt budget 25**, seed 42, fully offline and reproducible.

**Primary metric in this tier is EVASION** — the fraction of tasks where at least one mutated variant got past the shield unblocked. (Strict ASR — goal actually achieved — requires a live LLM behind the pipeline; see the full-pipeline tier below.)

| Attempts k | Cumulative evasion |
|---|---|
| 1 | 0.0% |
| 2 | **100.0%** |
| 3–25 | 100.0% |

Per-suite at budget: banking / slack / travel / workspace all 100% evaded. Strict ASR: 0.0% at every k (no LLM present to leak — by construction).

### Honest interpretation

1. **The deterministic tier is evadable within 2 attempts.** Attempt 1 (verbatim of a shuffled seed) was blocked for every task; attempt 2's mutated variant evaded for every task. This is exactly the CAISI warning: static, rule-based defenses degrade fast under budgeted adaptive pressure. It is why Archon ships the deterministic tier as a *free first line*, not the whole defense — and why the closed-loop purple verification (`archon purple --ci`) re-attacks after every policy change.
2. **Single-attempt numbers flatter static defenses.** The Tier-1 table above shows 33.3% block rate; under a 2-attempt adaptive attacker the deterministic tier's effective block rate is ~0%. Any vendor publishing single-shot numbers without an attempt-budget disclosure is likely overstating protection.
3. **This is the case for the full-pipeline tier.** The production stack adds LLM layers (dynamic invariants, Task Shield-style checks, exchange classifier) precisely for these structural wrappers. Publishing that number requires only `ARCHON_ATTACK_PROVIDER_API_KEY` + `archon_benchmarks.llm_tier.run_full_pipeline_benchmark()`.

Methodology declared per commitments: attempt_budget=25 · adaptivity=multi-attempt-5-variant-rotation · judge=deterministic-rules (evasion = pipeline not blocked). Reproduce:

```bash
uv run python -c "from archon_benchmarks.multi_attempt import run_multi_attempt_benchmark; print(run_multi_attempt_benchmark(max_attempts=25, seed=42)['evasion'])"
```
