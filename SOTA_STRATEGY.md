# ARCHON SOTA STRATEGY — Verified & Corrected (v3)

> **Date:** August 23, 2026 · **Branch:** `hackathon-v2` · **Supersedes:** earlier drafts of this strategy
> Every competitor claim below was re-verified against live sources Aug 22 and against cloned
> source code Aug 23. Where this document differs from prior strategy drafts, this version wins.
> Execution history now lives in [`BLUEPRINT_HACKATHON.md`](./BLUEPRINT_HACKATHON.md) §10 to avoid duplicate logs.

---

## 0. Status Correction (vs. older drafts)

Prior drafts state *"334/404 passing tests"*. Current reality:

| Area | Status |
|---|---|
| Tests | **649 passing / 3 skipped** |
| P0 enterprise blockers | ✅ **All closed**: HMAC-signed identity, `archon` CLI + CI gates, scrubbed OTel→Cloud Trace telemetry, policy versioning + audit trail, Postgres registry, Dockerfile/compose/wheel/Helm |
| P1 differentiators | ✅ **All shipped + expanded**: 120-probe OWASP-mapped corpus (encoding-evasion + latent-injection packs, false-positive canaries), MCP static + live behavioral scanning, compliance evidence reports with evidence-derived severity, Policy-CI baseline gates, fleet gate, community pack loader, ExternalGuardrailLayer |
| Post-hackathon sprints (Aug 23) | ✅ **ROADMAP COMPLETE**: live tool-execution battles w/ env-state ground truth, live memory/vector-store poisoning, ASI07 trust-boundary attacks, trace-driven attack generation, comparison engine + checkpoint/resume, Web UI dashboard, contrib gallery, Homebrew/npm distribution |
| Benchmarks | ✅ **AgentDojo v1 harness shipped**; deterministic-tier ASR published in [`RESULTS.md`](./RESULTS.md) |

Remaining from old plans: live Cloud Run deployment (needs GCP creds), demo video, Devpost package, full-pipeline benchmark run (LLM layers enabled), Claude-native attacker provider.

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

### 🟢 Shift 3: Garak keeps moving — GOAT now VERIFIED in code (Aug 23)
Garak is at **v0.16.1.pre1** with Context-Aware Scanning (CAS) + IntentProbe (self-described
"experimental and incomplete"). The earlier "unverified" flag on the GOAT claim is **resolved**:
`garak/probes/goat.py` exists (O-T-S-R attacker-LLM loop), alongside `tap.py` ×3,
`agent_breaker.py` (tool-analyzing multi-turn), and `latentinjection.py` ×8. Garak is a serious
multi-turn attacker now — but still scanner-only: no runtime defense, no defense evaluation,
no live tool sandbox, and compliance *tags* rather than adversarially-validated evidence.

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
> Remaining in C: ~~AgentDojo benchmark numbers~~ ✅ **DONE Aug 23** — `archon_benchmarks` + [`RESULTS.md`](./RESULTS.md).
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

> **Status (Aug 22, 2026):** items 7–8 shipped as code in Sprint C+ sessions (community pack loader
> + `archon plugins` inventory; `FleetSummary` + `archon fleet`). Enterprise hardening additions from
> the backlog also landed: `PostgresRegistry` behind `ARCHON_DATABASE_URL` and a production Helm chart
> (`deploy/helm/archon-armor/`, non-root + probes + /data volume). Suite 505 passing.

## 3.1 Execution log

> **Deduplicated Aug 23:** the full execution history (Sprints A–D, P0/P1 items, suite
> progression 286→649) now lives in [`BLUEPRINT_HACKATHON.md`](./BLUEPRINT_HACKATHON.md) §10.
> Latest entries: the post-hackathon sprint wave — corpus 102→120, severity derivation,
> sandbox/memory/multi-agent targets, trace-driven attacks, compare+checkpoint, Web UI,
> contrib gallery, distribution — and the deep competitive review that closed ROADMAP v4
> (suite 517→649), all Aug 23, 2026.
## 4. Hackathon (deadline Aug 31) — unchanged, still first

Everything in BLUEPRINT §5.3 stands: deploy armor to Cloud Run, Gemini/Gemma demo path, 4-min
video, blog + `#AllThingsAgenticHackathon`. The only update: the demo should *lean into* the new
positioning — show `archon scan --target <third-party-endpoint>` producing an evidence report
about someone else's guardrail. Nothing else on stage says that.

## 5. Corrections Log (vs. the prior strategy draft)

| Prior claim | Verdict | Correction |
|---|---|---|
| "Promptfoo ships OWASP Agentic ASI01–ASI10 plugins" | ✅ Verified in code | `constants/frameworks.ts` maps 9 frameworks incl. OWASP Agentic ASI01-10 (Dec 2025), MITRE ATLAS, NIST AI RMF, EU AI Act, ISO 42001, GDPR, DoD |
| "Promptfoo Hydra adapts dynamically" | 🟡 Corrected (code-verified) | The branching pattern is real but the adaptive brains run **cloud-side**; OSS ships provider stubs (`goblin.ts` admits it) |
| "Garak v0.15.0 GOAT probe + agent-breaker" | ✅ Verified in code Aug 23 | `probes/goat.py` + `probes/agent_breaker.py` exist in v0.16.1.pre1 |
| "PyRIT v0.13 AttackTechnique abstraction" | ✅ Superseded by v1.1 rewrite | Now scenario/registry architecture with `pyrit_scan` CLI + CoPyRIT GUI; still zero compliance mapping (grep-verified) |
| "97M+ MCP downloads / 82% vulnerable" | ❓ Unverified | Do not cite without source |
| "Status: 334/404 tests" | ❌ Stale | 649 tests; ROADMAP v4 fully closed (see §0) |
| "Window is 6–12 months" | 🔴 Too optimistic | Verified Guardrails/MCP-Proxy move ⇒ ~3–6 months |

---

*Maintained alongside code on `hackathon-v2`. Bump version/date on substantive edits.*


