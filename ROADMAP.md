# Archon Roadmap (v4 — rewritten against shipped reality)

> **Date:** August 23, 2026 · **Branch:** `hackathon-v2`
> This roadmap was rewritten on Aug 23 because the previous version still presented
> shipped capabilities as future work under `src/agentbeats/` paths that no longer exist.
> Everything below reflects what is actually in `packages/` today (**603 tests passing**).
> Strategy rationale lives in [`BLUEPRINT_HACKATHON.md`](./BLUEPRINT_HACKATHON.md);
> competitor context in [`COMPETITIVE_ANALYSIS.md`](./COMPETITIVE_ANALYSIS.md).

---

## ✅ Shipped (was "planned" in earlier roadmaps)

| Planned item | Shipped as | Where |
|---|---|---|
| Decouple from A2A / in-process execution | `TargetAdapter` ABC + `BattleManager` remote battles; A2A frozen behind compat layer | `packages/archon_core/targets/`, `archon_armor/battles.py` |
| Multi-provider support | `LLMProvider` ABC; OpenAI-compat + Gemini providers (Gemini is the default attack provider via OpenAI-compat) | `packages/archon_core/providers/` |
| YAML configuration | `archon scan --config archon.yaml`, flag-over-config precedence (`examples/archon.yaml`) | `packages/archon_core/config.py` |
| CLI with CI exit codes | `archon register / scan / scan-mcp / battle / serve / report / fleet / plugins` — all major commands emit JSON + exit codes | `packages/archon_cli/` |
| Probe corpus + OWASP mapping | 102 probes across all 10 OWASP LLM Top-10 categories + 12 benign false-positive canaries; Garak-lineage encoding_evasion (15) and latent_injection (15) packs | `packages/archon_armor/probes.py` |
| Community plugin packs | `load_pack_file()`, `ARCHON_CONTRIB_DIR` auto-load, `archon plugins` seam inventory | `probes.py`, `archon_cli/main.py` |
| Runtime defense product | archon-armor FastAPI OpenAI-compat proxy: HMAC identity, rate limiting, per-agent policy, output redaction | `packages/archon_armor/` |
| Enterprise governance | Versioned policies, immutable append-only audit trail, Postgres registry (`ARCHON_DATABASE_URL`) | `registry/versioned.py`, `registry/postgres.py`, `audit.py` |
| Observability | Real OTel SDK → Cloud Trace (`ARCHON_OTEL_EXPORTER=otlp`), PII scrubbing, JSONL fallback | `observability/otel.py`, `scrubbing.py`, `jsonl.py` |
| Packaging & deploy | Wheel, non-root Dockerfile, docker-compose, Helm chart (`deploy/helm/archon-armor/`) | repo root + `deploy/` |
| MCP security | Static tool-poisoning scan + live behavioral probing (`scan-mcp --url --probe-tool`) | `targets/mcp_scan.py`, `mcp_live.py` |
| Third-party guardrail validation | `archon scan --target <url>` + `ExternalGuardrailLayer` (NeMo/Model Armor/Promptfoo Guardrails become pluggable defenses AND attackable targets) | `targets/openai_compat.py`, `defenses/external.py` |
| Policy-CI (defense regression gates) | `BaselineStore` + `--update-baseline/--gate-baseline`; fleet gate via `archon fleet --ci` | `archon_armor/baselines.py`, `fleet.py` |
| Compliance evidence reports | OWASP-mapped HTML/MD battle reports | `reporting/compliance.py` |
| Adaptive multi-turn attacker | `BranchingAttacker` (Hydra-style fan-out/pivot/prune, deterministic verdicts) + multi-turn battles first-class | `attacks/branching.py` |
| Benchmark harness | AgentDojo v1: all 27 published injection tasks × 3 wrappers; published ASR in [`RESULTS.md`](./RESULTS.md) | `packages/archon_benchmarks/` |

---

## 🔜 Next (post-hackathon, priority order)

### Phase N1 — Credibility compounding (weeks 1–2)
1. **Full-pipeline benchmark run** — re-run the AgentDojo harness with LLM layers enabled; publish end-to-end ASR next to the deterministic-tier number in `RESULTS.md`.
2. **Attacker diversity** — `ClaudeNativeProvider` (+ optional local vLLM) under the existing `LLMProvider` seam; benchmark-driven tuning.

### Phase N2 — The unclaimed gaps (weeks 3–8)
*Each of these was verified absent-or-weak across all 9 competitor repos (see `COMPETITIVE_ANALYSIS.md` §10.5):*
4. ~~**Live tool-execution battles**~~ ✅ **SHIPPED (ahead of schedule)** — `targets/sandbox.py`: instrumented sandbox targets (mutable state, deep-copy snapshots, key-level diffs) with a deterministic directive planner and ground-truth goal checks over env diffs; `BranchingAttacker._probe` honors the env-state `attack_success` signal; closed-loop tests prove the shield stops what the vulnerable agent falls for.
5. ~~**Live memory/vector-store poisoning** — attacks against real stores, not simulated two-step scenarios.~~ **SHIPPED** (`targets/memory.py`: VectorMemoryStore + plant_poison + RetrievalAgentTarget; benign-query retrieval hijack proven, remediation scrubbing kills the attack).
6. ~~**Multi-agent trust-boundary attacks** — OWASP ASI07 exploitation (mapped by promptfoo, attacked by nobody).~~ ✅ **SHIPPED (ahead of schedule)** — `targets/multiagent.py`: `MultiAgentSwarm` (agents, delegation edges, transcript) + `TrustBoundaryTarget` modeling the ASI07 asymmetry — the coordinator sanitizes *direct* user input but trusts worker output blindly; directives smuggled through an untrusted worker cross the boundary and leak secrets. `sanitize_boundary=True` is the blue-team variant; closed-loop tests prove BranchingAttacker succeeds vs vulnerable swarm and fails vs sanitized.
7. ~~**True severity derivation**~~ ✅ **SHIPPED (ahead of schedule)** — `reporting/severity.py`: CVSS-style 0–10 scores derived from battle evidence (threat-class base × execution-mode exposure × evasion delivery), stable vector strings (`ARCHON:1/CAT:…/EXP:…/EV:…`), critical/high/medium/low bands, aggregated into every battle summary and rendered in HTML/Markdown evidence reports. Unlike DeepTeam's hardcoded impact, every component is derived.
8. ~~**Trace-driven attack generation**~~ ✅ **SHIPPED (ahead of schedule)** — `attacks/trace_driven.py`: mines JsonlTracer/OTLP-JSON span streams into a `TraceProfile` (layers that never fired, live tool names, leaked error internals, agent identities) and synthesizes targeted attacks — per-layer evasion payloads, tool-name-targeted injections, error-exploit extraction. `TraceAttack` duck-types the armor `Probe` contract so generated attacks flow straight into `BattleManager.execute`. Competitors only *evaluate* from traces; Archon *attacks* from them.

### Phase N3 — Ecosystem & distribution (months 2–3)
9. **Web UI dashboard** — battle results, coverage matrices, fleet view (read-only first).
10. **Comparison engine** — `archon compare` across registries/models/policy versions.
11. **Plugin marketplace directory** — curated `contrib/` gallery indexed in README; CI matrix for community pulls.
12. **Distribution breadth** — npm/Homebrew wrappers around the wheel; docs site.
13. **Caching/resume for long battles** — checkpoint battle state; resume interrupted campaigns.

### Phase N4 — Managed layer (month 3+)
14. Scheduled continuous battles across agent fleets; alerting on baseline regressions.
15. Multi-tenant armor control plane (the revenue layer over the MIT open core).

---

## Explicitly descoped (and why)

- **RL-adaptive attack strategies** — deterministic branching + provider-driven mutation covers the practical threat model at a fraction of the cost.
- **Own eval-quality metrics** — DeepEval/RAGAS own that space; Archon's helpfulness regression ("normal user test") covers the security-relevant slice.
- **Becoming a guardrail library** — NeMo/DeepTeam ship DIY guard libraries; Archon ships the *measurable enforcement point* plus the adversary that validates it.
