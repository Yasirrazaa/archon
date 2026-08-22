# ARCHON SOTA STRATEGY — Verified & Corrected (v2)

> **Date:** August 22, 2026 · **Branch:** `hackathon-v2` · **Supersedes:** earlier drafts of this strategy
> Every competitor claim below was re-verified against live sources today. Where this document
> differs from prior strategy drafts, this version wins.

---

## 0. Status Correction (vs. older drafts)

Prior drafts state *"334 passing tests, Phase 1–6 complete"*. Current reality:

| Area | Status |
|---|---|
| Tests | **404 passing** |
| P0 enterprise blockers | ✅ **All closed**: HMAC-signed identity, `archon` CLI + CI gates, scrubbed JSONL telemetry, policy versioning + audit trail, Dockerfile/compose/wheel |
| P1 differentiators | ✅ **All shipped**: OWASP-mapped probe packs + coverage matrix, MCP tool-poisoning scanner (`archon scan-mcp --ci`), compliance evidence reports (HTML/MD), Policy-CI baseline regression gates, GCP deployment guide |

Remaining from old plans: live Cloud Run deployment (needs GCP creds), ADK/Gemini live demo path, demo video, behavioral (live-server) MCP testing, AgentDojo benchmark runs, real gRPC OTLP exporter, YAML config, plugin entry-points.

## 1. Verified Market Shifts (Aug 22, 2026) — What Changed Today

### 🔴 Shift 1: Promptfoo has FIVE multi-turn attack strategies (CONFIRMED)
Live docs list **Crescendo, Hydra, Goblin, GOAT, Mischievous User**. Hydra coordinates a branching
attacker that remembers refusals and shares successful tactics across a scan.
→ **"Adaptive multi-turn attacks" is no longer a defensible differentiator on the attack side alone.**
Our deterministic signal extraction remains an engineering advantage, but the *category* is theirs now too.

### 🔴 Shift 2: Promptfoo is entering RUNTIME DEFENSE (CONFIRMED via product nav)
Their site now lists **Guardrails** ("real-time protection against jailbreaks and adversarial
attacks") and an **MCP Proxy** product. Docs pages are still thin/404 — early days — but the
direction is unambiguous: they are building exactly the red-team + runtime combination we thought
was 6–12 months away.
→ **The window is ~3–6 months, not 12.** Speed is now the primary strategic variable.

### 🟡 Shift 3: Garak keeps moving (partially verified)
Garak is at **v0.16.0 (Aug 2026)** working on intent/technique annotation and IntentProbe.
The claim that Garak shipped a "GOAT probe / agent-breaker" was **not verifiable in the release
notes reviewed** — treat as plausible-but-unconfirmed; do not use in public materials without checking.

### 🟡 Shift 4: OWASP Agentic Top-10 (2026) is published and peer-reviewed (CONFIRMED)
The exact risk numbering ("ASI01–ASI10") used in some drafts is **unverified** — refer to risks by
name until the official IDs are confirmed. AIUC-1 crosswalk also exists.

### ⚪ Unchanged conclusions
PyRIT remains endpoint-agnostic library-only; Model Armor remains a filter you cannot
adversarially validate yourself; AgentDojo remains benchmark-not-product; Snyk Agent Scan remains
static-only. **The red-vs-blue measurement loop remains unclaimed.**

## 2. The Repositioned Moat

With attack-side multi-turn commoditizing, the durable moat narrows to three things — all ours:

1. **The measurement loop.** Point *any* attacker (ours, Promptfoo's, PyRIT's) at *any* guardrail
   (ours, NeMo, Lakera, **even Promptfoo Guardrails**) and produce per-layer, replayable evidence.
   No vendor can honestly sell "validated protection" while being attackable by the open tool that
   validates everyone — including them.
2. **Policy-CI.** Defense regression gates in pipelines (`--gate-baseline`) — invented here, still unique.
3. **Open, self-hostable, budget-accounted everything.** Promptfoo's runtime products will be
   commercial and cloud-tethered; MIT-licensed armor stays the neutral option.

**Positioning line (updated):**
> *Everyone can now attack. Almost nobody can prove their defense works. Archon is the neutral
> validation layer for agent security: adaptive attacks in, adversarially-validated evidence out —
> including evidence about other vendors' guardrails.*

## 3. Revised 90-Day Execution Plan (post-verification)

Old plans assumed 12 months of runway. The verified Promptfoo Guardrails/MCP-Proxy move cuts that
to roughly a quarter. Ruthless re-prioritization:

### Sprint A (Weeks 1–2): Own "validates everyone"
1. **Remote target scanning** — `archon scan --target https://any-guardrail/v1` via
   `OpenAICompatProxyTarget`: point Archon's probe packs at *third-party* guardrail endpoints and
   emit evidence reports about **their** defenses. This is the single most differentiated,
   most viral capability available to us. (Core seam exists; mostly CLI + adapter plumbing.)
2. **Real OTLP exporter** (HTTP/protobuf or JSON) alongside the JSONL sink → Cloud Trace proof.

> **Status (Aug 22, 2026):** A1 ✅ `archon scan --target` (8 tests, suite 404→412) ·
> A2 ✅ `OtelTracer` on the real OTel SDK, `ARCHON_OTEL_EXPORTER=otlp` → Cloud Trace,
> scrubbed, `[otel]` extra (11 tests, suite 412→423).

### Sprint B (Weeks 3–5): Behavioral MCP before Promptfoo's MCP Proxy matures
> **Status (Aug 22, 2026):** B1 ✅ live MCP scanning `archon scan-mcp --url` over
> Streamable HTTP with the pattern engine on real tool metadata (10 tests, suite
> 423→433) · B2 ✅ YAML policy-as-code `archon scan --config archon.yaml`
> (`examples/archon.yaml`, 12 tests, suite 433→445). Remaining: tool-invocation
> battles (behavioral probing beyond metadata) — deferred to Sprint C alongside
> the Hydra-style attacker upgrade.

3. **Live `MCPTarget` adapter**: spawn/connect an MCP server, enumerate tools, run poisoning +
   confused-deputy battles against real tool calls (static scanner already shipped).
4. **YAML battle config** (`archon-config.yaml`) for policy-as-code security tests in Git.

### Sprint C (Weeks 6–9): Match their best attacker, keep our engine honest
> **Status (Aug 22, 2026):** C1 ✅ `BranchingAttacker` (`archon_core/attacks/branching.py`):
> Hydra-style fan-out/pivot/prune with deterministic response scoring — the LLM only
> mutates payloads, verdicts stay model-free (10 tests) · C2 ✅ behavioral MCP probing:
> `probe_tool()` invokes live tools with canonical injection payloads and judges replies;
> `archon scan-mcp --url ... --probe-tool NAME` (8 tests). Suite 445→463.
> Remaining in C: AgentDojo benchmark numbers (needs live datasets/models).
> **C3 ✅** multi-turn battles are now first-class: `BattleManager.execute(mode="multi_turn")`
> converts the attack tree into per-branch verdicts (`summary.attack_tree`), and
> `archon battle --target URL --goal G --seed S --ci` gates on attack success
> (exit 1 = defense failed). Attack provider via env (`ARCHON_ATTACK_PROVIDER_*`,
> Gemini OpenAI-compat by default). 6 tests; suite 463→469; live smoke verified.
5. **GOAT-loop upgrade**: add Hydra-style branching with shared refusal learnings across parallel
   conversation paths (our deterministic signal extraction makes this cheaper per attack than theirs).
6. **AgentDojo benchmark runs + published numbers** — researcher credibility while the category is hot.

### Sprint D (Weeks 10–13): Ecosystem lock-in
7. Plugin entry-points (`archon.plugins` group) + docs for all five seams; seed marketplace repo.
8. Fleet dashboard MVP (read-only views over armor telemetry) — groundwork for managed cloud.

## 3.1 Execution log

| Date | Item | Status | Evidence |
|---|---|---|---|
| Aug 22, 2026 | Sprint A1 — remote target scanning: `TargetAdapter`/`TargetResponse` seam, `OpenAICompatTarget` with deterministic refusal detection, `BattleManager.execute(target=...)` remote battles, `archon scan --target URL --pack owasp_llm_10 --ci` | ✅ Done | 8 TDD tests; suite 404→412 passing |
| Aug 22, 2026 | Sprint A2 — production OpenTelemetry: `OtelTracer` bridging the Tracer ABC onto the real OTel SDK (contextvar parenting, async-safe per-task span trees, OTLP type coercion), env factory (`ARCHON_OTEL_EXPORTER=none\|memory\|otlp`), server wiring with PII scrubbing preserved, `[otel]` extra in pyproject | ✅ Done | `observability/otel.py`, 11 TDD tests; suite 412→423 passing; spans export to Cloud Trace/Jaeger/any OTLP collector |
## 4. Hackathon (deadline Aug 31) — unchanged, still first

Everything in BLUEPRINT §5.3 stands: deploy armor to Cloud Run, Gemini/Gemma demo path, 4-min
video, blog + `#AllThingsAgenticHackathon`. The only update: the demo should *lean into* the new
positioning — show `archon scan --target <third-party-endpoint>` producing an evidence report
about someone else's guardrail. Nothing else on stage says that.

## 5. Corrections Log (vs. the prior strategy draft)

| Prior claim | Verdict | Correction |
|---|---|---|
| "Promptfoo ships OWASP Agentic ASI01–ASI10 plugins" | 🟡 Partially verified | Multi-turn strategies confirmed; exact ASI numbering unverified — use risk names |
| "Promptfoo Hydra adapts dynamically" | ✅ Verified | Branching attacker w/ shared tactics across scan |
| "Garak v0.15.0 GOAT probe + agent-breaker" | ❓ Unverified | v0.16.0 exists w/ IntentProbe; GOAT-probe claim not found in reviewed notes |
| "PyRIT v0.13 AttackTechnique abstraction" | ⚪ Plausible | Not re-verified today; no strategic impact |
| "97M+ MCP downloads / 82% vulnerable" | ❓ Unverified | Do not cite without source |
| "Status: 334 tests, Phase 1–6" | ❌ Stale | 404 tests; P0 + P1 complete (see §0) |
| "Window is 6–12 months" | 🔴 Too optimistic | Verified Guardrails/MCP-Proxy move ⇒ ~3–6 months |

---

*Maintained alongside code on `hackathon-v2`. Bump version/date on substantive edits.*


