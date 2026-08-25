# ARCHON SOTA STRATEGY — Verified & Corrected (v4)

> **Date:** August 23, 2026 · **Branch:** `hackathon-v2` · **Supersedes:** earlier drafts of this strategy
> Every competitor claim below was re-verified against live sources Aug 22 and against cloned
> source code Aug 23. Additional market intelligence gathered via web research Aug 23.
> Where this document differs from prior strategy drafts, this version wins.
> Execution history now lives in [`BLUEPRINT_HACKATHON.md`](./BLUEPRINT_HACKATHON.md) §10 to avoid duplicate logs.

---

## 0. Status Correction (vs. older drafts)

Prior drafts state *"334/404 passing tests"*. Current reality:

| Area | Status |
|---|---|
| Tests | **1,941 passing / 3 skipped** (CI-enforced, ≥85% coverage gate) |
| P0 enterprise blockers | ✅ **All closed**: HMAC-signed identity (+ ed25519 identity v2, attenuating tokens, nonce store), `archon` CLI + CI gates, scrubbed OTel→Cloud Trace telemetry, policy versioning + audit trail, Postgres registry + migrations, Dockerfile/compose/wheel/Helm, SECURITY.md threat model, cosign-signed SBOM releases |
| P1 differentiators | ✅ **All shipped + expanded**: 222-probe corpus (largest open agentic corpus, ahead of Garak's 195), MCP static + live behavioral scanning, compliance evidence reports with evidence-derived severity, Policy-CI baseline gates, fleet gate, community pack loader, ExternalGuardrailLayer, kill-switch w/ MTTC, purple runs, shadow mode, plan-divergence detection |
| Post-hackathon sprints | ✅ **ROADMAP COMPLETE through Phase E2.11**: live tool/memory/multi-agent/MCP/supply-chain/cascade/trust/rogue attack targets, trace-driven generation, comparison engine + checkpoint/resume, Web UI, contrib gallery, Homebrew/npm distribution, ADK adapter, multi-tenancy v1, FinBot CTF adapter |
| Benchmarks | ✅ **Full published ladder in RESULTS.md**: AgentDojo deterministic 66.7%/FPR 0% → Tier-3 full-pipeline 27.2% → InjecAgent → strict-ASR 18.5% (evasion ≠ compromise) → per-target ground-truth 81.8% → pass^k 11/11=1.0 → R-Judge judge-agreement 89.2% (at human ceiling) — all with attempt-budget/adaptivity/judge methodology blocks |

Remaining from old plans: live Cloud Run deployment (user-side, needs GCP creds), demo video, Devpost submission, GitHub Pages enablement.

## 0.1 The Maturity Thesis (Aug 23 audit + landscape research)

Internal code-quality audit verdict (Aug 23, at 649 tests): **B+ hackathon, C+ enterprise** —
no CI pipeline, no lint/type gates, legacy packaging, no release process, SQLite-first
persistence, and no self threat model.
Combined with the [`LANDSCAPE_2026.md`](./docs/LANDSCAPE_2026.md) research:

> **The hard part is done. What's missing is the boring 80%: CI, packaging hygiene, docs,
> persistence, and community. That is exactly why promptfoo wins deals despite weaker agentic
> attack technology than Archon now has. Enterprises buy operational maturity; researchers
> buy capability.**

Strategic consequence: **Phase E0 (engineering maturity) executed before any new capability
work — DONE** (all six audit gaps closed; see ROADMAP gap table), then E2.5–E2.9 converted
the landscape research into differentiators competitors can't copy quickly (adaptive
multi-attempt methodology per CAISI's 11%→81% finding, UAR/PED metrics productization,
MCP/A2A protocol-layer inspection, compliance evidence automation against AIUC-1/CSA STAR
certification schemes). Full detail in ROADMAP.md v5.1.

---

## 1. Verified Market Shifts (Aug 22–23, 2026) — What Changed Today

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

### 🔴 Shift 3: Augustus (Praetorian) validates the market but doesn't address defense evaluation
Augustus v0.0.9 ships 210+ probes across 47 attack categories with 4 multi-turn strategies
(Crescendo, GOAT, Hydra, Mischievous User). This validates the market for agent security testing
but confirms that scanner-only tools are commodity — the durable moat is defense evaluation.
→ **The red-vs-blue measurement loop remains unclaimed by any new entrant.**

### 🟢 Shift 4: Garak keeps moving — GOAT now VERIFIED in code (Aug 23)
Garak is at **v0.16.1.pre1** with Context-Aware Scanning (CAS) + IntentProbe (self-described
"experimental and incomplete"). The earlier "unverified" flag on the GOAT claim is **resolved**:
`garak/probes/goat.py` exists (O-T-S-R attacker-LLM loop), alongside `tap.py` ×3,
`agent_breaker.py` (tool-analyzing multi-turn), and `latentinjection.py` ×8. Garak is a serious
multi-turn attacker now — but still scanner-only: no runtime defense, no defense evaluation,
no live tool sandbox, and compliance *tags* rather than adversarially-validated evidence.

### 🟡 Shift 5: OWASP Agentic Top-10 (2026) is published and peer-reviewed (CONFIRMED)
The exact risk IDs are confirmed as **ASI01–ASI10** (per DeepTeam's integration and Auth0's analysis):
- ASI01: Agent Goal Hijack
- ASI02: Tool Misuse & Exploitation
- ASI03: Agent Identity & Privilege Abuse
- ASI04: Agentic Supply Chain Compromise
- ASI05: Unexpected Code Execution
- ASI06: Memory & Context Poisoning
- ASI07: Insecure Inter-Agent Communication
- ASI08: Cascading Agent Failures
- ASI09: Human-Agent Trust Exploitation
- ASI10: Rogue Agents

~~Archon covers 6/10 today~~ **(superseded Aug 25: Archon covers 10/10 — full ASI01–10 live attack coverage)** (ASI01, ASI02, ASI06, ASI07, + partial ASI03/ASI05). Gap: ASI04, ASI08, ASI09, ASI10.

### ⚪ Unchanged conclusions
PyRIT remains endpoint-agnostic library-only; Model Armor remains a filter you cannot
adversarially validate yourself; AgentDojo remains benchmark-not-product; Snyk Agent Scan remains
static-only. **The red-vs-blue measurement loop remains unclaimed.**

---

## 2. The Repositioned Moat

With attack-side multi-turn commoditizing, the durable moat narrows to **four things** — all ours:

1. **The measurement loop.** Point *any* attacker (ours, Promptfoo's, PyRIT's, Augustus's) at *any* guardrail
   (ours, NeMo, Lakera, **even Promptfoo Guardrails**) and produce per-layer, replayable evidence.
   No vendor can honestly sell "validated protection" while being attackable by the open tool that
   validates everyone — including them.

2. **Policy-CI.** Defense regression gates in pipelines (`--gate-baseline`) — invented here, still unique.

3. **Open, self-hostable, budget-accounted everything.** Promptfoo's runtime products will be
   commercial and cloud-tethered; MIT-licensed armor stays the neutral option.

4. **OWASP Agentic Top-10 coverage.** Archon is the only tool that both *tests* and *defends*
   against ASI01-ASI10 risks with adversarially-validated evidence. DeepTeam maps them;
   Promptfoo maps them; but nobody *executes* the attacks and *proves* the defenses work.

**Positioning line (updated):**
> *Everyone can now attack. Almost nobody can prove their defense works. Archon is the neutral
> validation layer for agent security: adaptive attacks in, adversarially-validated evidence out —
> including evidence about other vendors' guardrails.*

---

## 3. Revised 90-Day Execution Plan (post-verification)

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
> **Status (Aug 22, 2026):** C1 ✅ `BranchingAttacker` · C2 ✅ behavioral MCP probing ·
> C3 ✅ multi-turn battles first-class · Remaining: ~~AgentDojo benchmark numbers~~ ✅ **DONE Aug 23**.

5. **GOAT-loop upgrade**: add Hydra-style branching with shared refusal learnings across parallel
   conversation paths (our deterministic signal extraction makes this cheaper per attack than theirs).
6. **AgentDojo benchmark runs + published numbers** — researcher credibility while the category is hot.

### Sprint D (Weeks 10–13): Ecosystem lock-in
7. Plugin entry-points (`archon.plugins` group) + docs for all five seams; seed marketplace repo.
8. Fleet dashboard MVP (read-only views over armor telemetry) — groundwork for managed cloud.

> **Status (Aug 22, 2026):** items 7–8 shipped as code. Enterprise hardening: Postgres registry + Helm chart.
> Suite 505 passing.

### Sprint E (Weeks 14–26): Enterprise readiness
9. **Full-pipeline benchmark** — re-run AgentDojo with LLM layers enabled; publish end-to-end ASR.
10. **Attacker diversity** — local vLLM via existing `OpenAICompatProvider`; benchmark-driven tuning. (ClaudeNativeProvider ✅ already shipped, commit e37305c.)
11. **ASI04/ASI08/ASI09/ASI10 coverage** — close the OWASP Agentic Top-10 gap.
12. **HarmBench integration** — published numbers for researcher credibility.
13. **Docs site + live demo** — persistent documentation and demonstration.
14. **Managed cloud control plane** — multi-tenant armor deployments, scheduled battles, alerting.

---

## 4. Hackathon (deadline Aug 31) — unchanged, still first

Everything in BLUEPRINT §5.3 stands: deploy armor to Cloud Run, Gemini/Gemma demo path, 4-min
video, blog + `#AllThingsAgenticHackathon`. The only update: the demo should *lean into* the new
positioning — show `archon scan --target <third-party-endpoint>` producing an evidence report
about someone else's guardrail. Nothing else on stage says that.

---

## 5. Corrections Log (vs. the prior strategy draft)

| Prior claim | Verdict | Correction |
|---|---|---|
| "Promptfoo ships OWASP Agentic ASI01–ASI10 plugins" | ✅ Verified in code | `constants/frameworks.ts` maps 9 frameworks incl. OWASP Agentic ASI01-10 (Dec 2025), MITRE ATLAS, NIST AI RMF, EU AI Act, ISO 42001, GDPR, DoD |
| "Promptfoo Hydra adapts dynamically" | 🟡 Corrected (code-verified) | The branching pattern is real but the adaptive brains run **cloud-side**; OSS ships provider stubs (`goblin.ts` admits it) |
| "Garak v0.15.0 GOAT probe + agent-breaker" | ✅ Verified in code Aug 23 | `probes/goat.py` + `probes/agent_breaker.py` exist in v0.16.1.pre1 |
| "PyRIT v0.13 AttackTechnique abstraction" | ✅ Superseded by v1.1 rewrite | Now scenario/registry architecture with `pyrit_scan` CLI + CoPyRIT GUI; still zero compliance mapping (grep-verified) |
| "97M+ MCP downloads / 82% vulnerable" | ❓ Unverified | Do not cite without source |
| "Status: 334/404 tests" | ❌ Stale | Now **1,941 tests**, CI-enforced; ROADMAP fully closed through Phase E2.11 (see §0) |
| "Window is 6–12 months" | 🔴 Too optimistic | Verified Guardrails/MCP-Proxy move ⇒ ~3–6 months |
| "OWASP Agentic ASI01-10 IDs unverified" | ✅ Verified | Confirmed via DeepTeam integration and Auth0 analysis: ASI01–ASI10 |
| "Augustus doesn't exist" | ❌ New competitor | Praetorian's Augustus v0.0.9: 210+ probes, 4 multi-turn strategies, Go-based |
| "Archon covers 6/10 OWASP Agentic risks" | ✅ Honest assessment → superseded | At audit: ASI01/02/06/07 + partial ASI03/05. **Now 10/10 full** (ASI03/04/08/09/10 closed by waves 1–2 + identity v2; ASI05 closed Aug 24 by targets/code_exec.py — sleeper-agent/sandbox-escape/destructive battles) |

---

*Maintained alongside code on `hackathon-v2`. Bump version/date on substantive edits.*
