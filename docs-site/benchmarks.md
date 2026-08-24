# Benchmarks

Published numbers, honestly scoped. Canonical source:
[`RESULTS.md`](https://github.com/Yasirrazaa/archon/blob/main/RESULTS.md).
Every number below carries its attempt budget, adaptivity level, and judge method —
because NIST CAISI showed single-attempt scores understate attack success by up to 70 points.

## The ladder (defense-side, AgentDojo v1 corpus unless noted)

| Tier | What it measures | Result |
|---|---|---|
| Deterministic tier (81 attacks) | Normalization + rule classification, **0 LLM calls** | ASR **66.67%** / block 33.33% · direct-override ASR **0.0%** |
| False-positive rate | 12 benign canaries through the same tier | **0.0%** over-refusal (0/12) |
| Tier-3 full pipeline (+ live Gemini upstream) | Defense-in-depth end-to-end: deterministic tier + model-native safety | ASR **27.2%** (27 blocked pre-upstream, 54 reached the model, 22 complied) |
| Multi-attempt evasion curves (budget 25) | Static rules under adaptive pressure | evasion 0% @ attempt-1 → **100% @ attempt-2** |
| Strict multi-attempt ASR (budget 5, live model) | Evasion vs actual compromise — per WASP dual-ASR | evasion 100% vs **strict compromise 18.5%** (median 3 attempts-to-compliance) |
| Per-target ground-truth series (11 live targets) | Adaptive attacker vs sandbox/memory/multi-agent/MCP/supply-chain/cascade/trust/rogue targets; success = environment state diff | ASR **81.8%** (27/33), zero LLM calls |
| tau-bench pass^k consistency (seeds 42/43/44) | Exploitability stability across seeds | **11/11 targets pass^k = 1.0** |
| InjecAgent (1,054 tool-injection cases) | Polite imperatives inside JSON tool output | deterministic tier 0% block / 100% ASR → why LLM layers exist |
| R-Judge judge agreement (571 records) | Heuristic judge floor | accuracy 47.6% / F1(unsafe) 0.063 |
| R-Judge LLM-judged (gemini-3.1-flash-lite via Archon's declared-judge harness) | Judge quality on naturalistic trajectories | **accuracy 89.2% / F1 0.893** — at the human-agreement ceiling (89.07%); GPT-4o's published F1 is 74.4% |

## Reading these numbers honestly

- The deterministic tier spends **zero** defensive LLM calls. Task Shield and spotlighting
  spend 1+ per request (Task Shield publishes 2.07% ASR). The structural wrappers that pass
  this tier are exactly what production LLM layers catch.
- Tier-3's 27.2% shows defense-in-depth measured end-to-end at zero defensive LLM spend;
  the residual is precisely what Archon's LLM defense layers target.
- "Evasion ≠ compromise": publishing evasion alone overstates compromise by >5× in our runs.
  We publish both, per WASP dual-ASR.

Reproduce: `uv run python -m archon_benchmarks.runner` (deterministic),
`run_full_pipeline_benchmark()` / `run_strict_asr_benchmark()` / `run_injecagent_benchmark()`
(env-gated with an API key), `run_target_series()` / `run_passk()` (offline).

Status: all tiers above are published. Still pending: LLM-brain
(GOAT-style) validation at CAISI-scale attempt budgets, which requires a
high-quota API key; our free-tier validation run is documented in RESULTS.md.
