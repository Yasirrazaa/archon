# Archon — Competitive & Market Analysis (v4)

> **Date:** August 23, 2026 · **Method:** every tool claim below was verified against live vendor docs/repos on Aug 22 and against **cloned source code** of 9 competitors (garak, promptfoo, PyRIT, NeMo Guardrails, AgentDojo, Snyk agent-scan, DeepTeam, DeepEval, RAGAS) on Aug 23. Additional market intelligence gathered via web research Aug 23. Star counts are approximate (±0.2k). Historical versions of this file contained errors — see the Corrections Log at the end.

---

## 1. Executive Summary

The LLM/agent security market has consolidated into **five distinct layers**, and **no single open-source tool spans them all**:

1. **Static scanning** of models/configs (Garak; Snyk Agent Scan for MCP/skills; Augustus)
2. **Eval-style red teaming** inside dev workflows (Promptfoo — now part of OpenAI; DeepTeam)
3. **Campaign attack orchestration** (PyRIT — multi-turn, endpoint-agnostic library)
4. **Runtime guardrails** (Google Model Armor, NeMo Guardrails, LLM Guard, Lakera Guard)
5. **Governance & access control** (Obot for MCP gateway; Zenity for agent governance)

Agent-specific testing exists only as a benchmark (**AgentDojo**, ETH Zurich) and static scanners (Snyk Agent Scan) — nobody offers *continuous, behavioral, red-vs-blue agent testing with a shippable defense*. That is Archon's wedge: proven multi-turn attack engine + packaged measurable defense proxy + extensible core.

### Market Size & Growth

The global AI Security Testing Platform market is projected to grow from **$769M (2025) to $2.1B by 2035** (YH Research, Aug 2026). AI agent security specifically is one of the fastest-growing subsegments, driven by enterprise adoption of agentic frameworks (Google ADK, LangChain, CrewAI) and the explosion of MCP tool integrations.

---

## 2. Verified Competitor Matrix (Aug 23, 2026)

### 2.1 Open-source leaders (verified against cloned source code)

| Tool | Owner | Stars | License | What it actually does | Real weaknesses (honest, code-verified) |
|---|---|---|---|---|---|
| **Promptfoo** v0.122 | **Part of OpenAI** (per its own README; remains MIT) | ~24.5k | MIT | ~150 red-team plugins × ~35 strategies incl. **5 multi-turn strategies** (Crescendo, Hydra, Goblin, GOAT, Mischievous User); real MCP target provider driving live tool calls; OTel GenAI tracing; **9 compliance frameworks** (OWASP LLM/API/Agentic ASI01-10, MITRE ATLAS, NIST AI RMF, EU AI Act, ISO 42001, GDPR, DoD); code-scanning product; **Guardrails** (runtime protection, cloud client); **MCP Proxy** product | Adaptive multi-turn **brains (Hydra/Goblin/Crescendo) run in promptfoo's cloud** — OSS ships provider stubs (`goblin.ts`: "the provider and cloud task own the behavior"); guardrails are a paid cloud API client, not a self-hosted proxy; memory/RAG poisoning is simulated two-step, not live-store attacks; Node ≥22 only; **vendor grades its own homework** |
| **Garak** v0.16.1 | NVIDIA | ~8.9k | Apache-2.0 | 195 probes / 122 detectors / 45 generators / 7 buffs; named attacks: **GOAT** (O-T-S-R attacker loop), TAP×3, Latent Injection×8, **Agent Breaker** (tool-analyzing multi-turn), GCG, AutoDAN; strongest compliance tagging (OWASP LLM01-10, AVID export, MISP ~180 tags, CWE, DeMIS, LMRC) | Scanner only — **zero runtime defense**; no live tool-execution sandbox, no environment-state verification, no multi-agent; new Context-Aware Scanning (CAS) self-described as "experimental and incomplete" |
| **PyRIT** v1.1.0.dev | Microsoft | ~4.3k | MIT | Deepest attack orchestration: Crescendo/PAIR/TAP/SkeletonKey/ManyShot + ~90 converters + 94 jailbreak templates + 59 dataset loaders; scenario matrix builder; CentralMemory provenance; `pyrit_scan` CLI + CoPyRIT GUI | **No compliance mapping anywhere in code** (biggest gap); agent surface thin (XPIA workflow + ATR dataset only — no MCP orchestrator, no memory/RAG attacks); Azure-leaning deps |
| **NeMo Guardrails** v0.24.0.dev | NVIDIA | ~7.0k | Apache-2.0 | Runtime defense product: LLMRails (Colang) + experimental IORails validating proxy (OpenAI wire only); ~30 guard integrations; streaming tool-call rails fail-closed; `/v1/checks` sidecar | **Zero offensive testing — cannot validate its own guards**; zero compliance mapping (grep-confirmed); tool rails are schema-level only (no env-state verification); heavy third-party detection glue |
| **AgentDojo** v0.1.35 | ETH Zurich Spy Lab | ~762 | MIT | NeurIPS 2024 benchmark: 86 user + 27 injection tasks, ~108 tools, FunctionsRuntime sandboxed execution with DeepDiff env-state ground truth (best-in-class instrumented environments); only 4 defenses | Benchmark not product; 14 attack classes mostly static templates; single threat class (indirect injection); slow cadence (last commit Jun 2026) |
| **Snyk Agent Scan** v0.6 (ex mcp-scan) | Snyk | ~2.9k | Apache-2.0 | Supply-chain static scanning: discovers 13 agents, 15 risk indicators (0-1000), Toxic Flows combination analysis; unique Agent Guard hooks into Claude Code/Cursor/Codex; partnered with Vercel for skills.sh ecosystem | **Never executes attacks** — analysis is a closed Snyk-API black box; enforcement cloud-side; no OWASP mapping; closed to contributions |
| **DeepTeam** v1.0.9 | Confident AI | ~1.7k | Apache-2.0 | 38 vulnerability classes / 124 sub-types (11 agentic), 27 attacks (5 multi-turn), ~56 judge metrics, 7 frameworks incl. **OWASP ASI 2026**; CVSS module; TraceScanner/CodeScanner | Everything flows through a text callback — **no live tool/MCP interception, no real store poisoning**; CVSS impact hardcoded MEDIUM; guards are DIY library calls, no proxy |
| **DeepEval** v4.1.10 / **RAGAS** v0.4.3 | Confident AI / vibrantlabsai | 13.9k / 12.8k | Apache-2.0 | Eval-only: ~56 quality metrics (agentic: TaskCompletion, ToolCorrectness, MCP×3) / ~36 RAG metrics + KG testset synthesis | Zero security dimension (red teaming split out to DeepTeam post-v3); RAGAS cadence stalled Feb 2026 |
| **Augustus** v0.0.9 | Praetorian | ~1.2k | Apache-2.0 | Go-based LLM vulnerability scanner: **210+ adversarial probes** across 47 attack categories; **4 multi-turn strategies** (Crescendo, GOAT, Hydra, Mischievous User — mirrors Promptfoo's); tests 28+ LLM providers | Scanner only — no runtime defense, no defense evaluation, no live tool sandbox; Go-based (not Python ecosystem); no compliance mapping |

### 2.2 Platforms & commercial context

| Tool | Owner | Type | What it does | Archon angle |
|---|---|---|---|---|
| **Google Cloud Model Armor** | Google | Commercial (GA) | Bidirectional prompt/response screening; integrates Vertex AI, Apigee, Agent Gateway, LangChain, MCP servers; PII detection, jailbreak/prompt-injection blocking, malicious URL filtering | Complementary — Archon can *validate* Model Armor defenses with per-layer evidence; hackathon track namesake |
| **Lakera Guard/Red** | Lakera (Check Point) | Commercial | Runtime AI security: 98%+ prompt injection detection; full-lifecycle agent security (discovery → risk assessment → runtime enforcement) | Archon validates what Lakera defends — different layer of the stack |
| **Obot** | Obot | Open-source (MIT) | MCP gateway & governance: centralized control plane for MCP servers, credential management, fine-grained tool-level permissions, RBAC, audit logging | Governance layer — Archon focuses on security testing, not access control |
| **Guardrails AI** | Guardrails AI | Open-source (MIT) | Structured validation & I/O guards: composable validators (PII, toxicity, prompt injection), SDK-based, modular PyPI packages | Runtime validation library — Archon ships measurable enforcement + adversary that validates it |
| **NeuralTrust** | NeuralTrust | Commercial | AI runtime security platform; compares favorably to Lakera in independent reviews | Enterprise runtime security — Archon validates defenses, doesn't replace them |
| **Zenity** | Zenity | Commercial | Agent governance for Microsoft-heavy orgs; furthest among early startups | Enterprise governance — different layer |
| **HiddenLayer** | HiddenLayer | Commercial | AI threat detection & response | Enterprise security — different layer |
| **Mindgard** | Mindgard | Commercial | AI security testing platform | Direct competitor in testing space — but closed-source, no open red/blue loop |
| **Haize Labs** | Haize Labs | Commercial | AI red teaming as a service | Service, not tool — Archon is self-hostable |
| **Protect AI → Palo Alto Networks** | Palo Alto | Commercial | LLM Guard (input/output filtering); acquired by Palo Alto Networks (2025) | Runtime filtering — no behavioral testing, no defense evaluation |
| **Check Point AI Security** | Check Point | Commercial | Enterprise AI security suite including Lakera integration | Enterprise suite — different layer |

### 2.3 The structural gap nobody fills

Buyers must currently stitch ≥3 tools: a scanner (Garak/Promptfoo/Augustus) for pre-deployment probes, an orchestration library (PyRIT) for campaigns, and a separate runtime guardrail (Model Armor / LLM Guard / NeMo / Lakera) whose effectiveness they can never *measure*. **The unclaimed position: one platform where attack, defense, and observability meet — point Archon's attacker at Archon's (or anyone's) defense and get evidence, not vibes.**

Three artifacts required — none of the competitors have all three:
1. Multi-turn stateful attack engine with deterministic signal extraction ✅ *(exists today)*
2. Defense pipeline packaged as a drop-in runtime proxy with per-layer telemetry ✅ *(shipped: archon-armor)*
3. Extensible core where third parties add strategies/layers/providers via stable ABCs ✅ *(shipped: five seams + community pack loader)*

---

## 3. The Gap Archon Owns

| Capability | Archon | Best alternative |
|---|---|---|
| Multi-turn stateful attacks w/ deterministic signals | ✅ | PyRIT (library UX), AgentDojo (fixed benchmark), Augustus (scanner) |
| Attack **and** defense in one framework | ✅ | AgentDojo evaluates both, but static/benchmark-only |
| Defense shipped as drop-in runtime proxy with per-layer telemetry | ✅ | Model Armor filters, gives filter verdicts — not adversarially validated by you |
| Helpfulness regression ("normal user test") alongside security | ✅ | ❌ nobody |
| Extensible via stable ABCs across attack/defense/provider/target/reporter seams | ✅ | Garak's plugin system is probe-side only |
| Red-vs-blue validation loop | ✅ | ❌ nobody — this is the durable moat |

---

## 4. Threat & Standards Alignment (OWASP Agentic Top-10 mapping)

The **OWASP Top 10 for Agentic Applications (2026)** is now published and peer-reviewed (Dec 2025, 100+ industry experts). The exact risk IDs are confirmed as ASI01–ASI10:

| OWASP Agentic risk (2026 Top-10) | ID | Archon coverage today | Planned |
|---|---|---|---|
| Agent Goal Hijack | ASI01 | ✅ core attack surfaces + L0–L4 defenses | — |
| Tool Misuse & Exploitation | ASI02 | ✅ MCP static scan + live behavioral probing + sandbox targets | — |
| Agent Identity & Privilege Abuse | ASI03 | ⚠️ HMAC identity, but no privilege escalation testing | policy-aware targets |
| Agentic Supply Chain Compromise | ASI04 | ⚠️ MCP tool-poisoning scan | schema manipulation attacks |
| Unexpected Code Execution | ASI05 | ✅ Full | `targets/code_exec.py` battle suite (sleeper agent, sandbox escape, destructive commands) + defenses |
| Memory & Context Poisoning | ASI06 | ✅ live memory/vector-store poisoning | — |
| Insecure Inter-Agent Communication | ASI07 | ✅ ASI07 trust-boundary attacks (closed-loop) | — |
| Cascading Agent Failures | ASI08 | ✅ Full (cascade target) | cascade-recovery targets |
| Human-Agent Trust Exploitation | ASI09 | ✅ Full (approval-fatigue target) | social-engineering targets |
| Rogue Agents | ASI10 | ✅ Full (rogue stego target) | rogue-agent detection |

Aligning terminology to this table in the Devpost description signals fluency to judges.

---

## 5. Enterprise Readiness Scorecard (post Phase 5 — Aug 2026)

Scale: **0 = absent · 1 = partial · 2 = best-in-class**. Archon column reflects code on `hackathon-v2` (**2,093 tests**, Aug 25, post-wave-12).

| # | Enterprise dimension | **Archon v3** | Promptfoo | Garak | PyRIT | NeMo Guard | Model Armor | Snyk Agent Scan |
|---|---|---|---|---|---|---|---|---|
| 1 | Multi-turn adaptive attack engine | **2** ✅ | 1 (brains cloud-side) | **2** (GOAT/TAP/Agent Breaker) | **2** | 0 | 0 | 0 |
| 2 | Defense evaluation (red vs blue loop) | **2** ✅ unique | 0 | 0 | 0 | 0 | 0 | 0 |
| 3 | Runtime defense as deployable product | **2** ✅ armor proxy + Helm | 1 (cloud client only) | 0 | 0 | **2** | **2** | 1 (hooks, cloud-enforced) |
| 4 | Per-layer defense telemetry (measurable defense) | **2** 🆕 unique | 1 | 0 | 0 | 1 | 1 (filter verdicts only) | 0 |
| 5 | Agent identity/registry/policy governance | **2** ✅ HMAC identity, versioned policies, audit trail | 0 | 0 | 0 | 0 | **2** (GCP IAM) | 0 |
| 6 | Observability & audit evidence | **2** ✅ OTel→Cloud Trace, scrubbed, immutable audit | 1 | 1 | 0 | 1 | **2** | 1 |
| 7 | CI/CD developer experience (CLI, exit codes) | **2** ✅ scan/battle/fleet/report/compare all `--ci` | **2** | 1 | 1 (`pyrit_scan`) | 1 | n/a | **2** |
| 8 | Threat/probe corpus breadth | **2** ✅ (222 probes post-wave-11 — now the largest open agentic-security corpus, ahead of Garak's 195; benchmark-backed via published AgentDojo numbers, per-target ground-truth series ASR 81.8%, FPR 0%; live-execution attack classes nobody else has) | **2** (~150 plugins) | **2** (195 probes) | **2** (94 templates + 59 datasets) | 0 | internal | 1 (static MCP) |
| 9 | MCP/tool-surface testing | **2** ✅ static scan + live behavioral probing | 1 (real MCP target) | 0 | 0 | 1 (schema rails) | 1 (integration) | **2** (static, closed analysis) |
| 10 | Production hardening (authN/Z, HA, multi-tenant) | **2** ✅ HMAC+rate-limit, Postgres, Helm non-root | 1 | 0 | 0 | 1 | **2** | 1 |
| 11 | Open source + self-hostable | **2** | **2** | **2** | **2** | **2** | 0 | 2 (no contribs) |
| 12 | Cost efficiency (LLM-budget accounting built-in) | **2** ✅ | 0 | 0 | 0 | 0 | token-priced | n/a |

### 5.1 Agentic attack-surface scorecard (post-N3 — Aug 23, 2026)

The dimensions that define *agent* security in 2026. Scale as above; DeepTeam and AgentDojo added as columns because they compete specifically here.

| # | Agentic dimension | **Archon** | Promptfoo | Garak | PyRIT | DeepTeam | AgentDojo | NeMo Guard |
|---|---|---|---|---|---|---|---|---|
| A1 | Live tool-execution attacks w/ env-state ground truth | **2** ✅ sandbox targets, `attack_success` from state diff | 1 (text-callback simulation) | 1 (chats about tools, no sandbox) | 0 | 1 (text callbacks only) | **2** (envs, but static templates) | 0 |
| A2 | Live memory/vector-store poisoning | **2** ✅ real store manipulation + remediation loop | 1 (simulated two-step scenario) | 0 | 0 | 1 (metric-only) | 0 | 0 |
| A3 | ASI07 multi-agent trust-boundary attacks | **2** ✅ boundary-crossing exploit, closed-loop vs sanitized variant | 1 (maps ASI07, doesn't attack it) | 0 | 0 | 1 (metric-only) | 0 | 0 |
| A4 | Evidence-derived severity scoring | **2** ✅ every component derived from battle evidence | 1 (severity tiers) | 1 (taxonomy tags) | 0 | 1 (impact hardcoded MEDIUM) | 0 | 0 |
| A5 | Trace-driven attack generation | **2** ✅ mines spans into targeted attacks | 1 (trace-driven evaluation only) | 0 | 0 | 1 (TraceScanner evaluates only) | 0 | 0 |
| A6 | Policy-version comparison engine | **2** ✅ `archon compare` + regression CI gate | 0 | 0 | 0 | 0 | 0 | 0 |
| A7 | Fleet dashboard UI | **2** ✅ zero-dependency `/ui` | **2** (local web viewer) | 1 (HTML report file) | 1 (CoPyRIT GUI) | 0 | 0 | 0 |

**Reading the tables:** nobody scores ≥2 on rows 1+3+4 simultaneously except Archon. That triple — *adaptive attacks, a shippable defense, and proof that the defense works* — is the company-making position. On the agentic rows (§5.1), Archon is the only project at **2** on A1–A6; no competitor holds more than one partial.

---

## 6. Market Timing

- **Agentic adoption is exploding** — agent frameworks (Google ADK, LangChain, CrewAI), MCP ecosystem growth (millions of downloads), while security tooling remains either scanner-era or benchmark-era.
- **OpenAI acquiring Promptfoo** validates M&A appetite for this category; **Snyk acquiring Invariant Labs** shows agent-security consolidation has already started; **Palo Alto acquiring Protect AI** validates enterprise budgets.
- **Google Cloud Model Armor GA** validates the runtime defense category — and positions Archon as the tool that *validates* those defenses.
- **OWASP Agentic Top-10 (2026)** publication creates a standards vocabulary that Archon can map to natively.
- **The winning open-source position** is the one developers can self-host and extend **before** platform vendors close it off.

### Key market dynamics (verified Aug 23, 2026)

- Promptfoo is now OpenAI-owned and expanded to a **5-product security suite** (Red Teaming, Guardrails, Model Security, MCP Proxy, Code Scanning), shipping weekly. This validates the category (offense + defense are one problem) and is their neutrality weakness ("vendor grades its own homework").
- Snyk Agent Scan absorbed the Invariant MCP-scan line; v0.6 is risk-scored but closed to contributions and depends on Snyk's hosted API. The live-behavior MCP lane is open.
- Garak stays a scanner (not a platform); PyRIT added a GUI; NeMo Guardrails added telemetry-style audit — none shrink the red/blue gap.
- **Augustus (Praetorian)** is a new entrant with 210+ probes and 4 multi-turn strategies — validates the market but doesn't address defense evaluation.
- **Obot** focuses on MCP governance/access control — complementary to Archon's security testing focus.
- Cloud/security incumbents (Datadog, CrowdStrike, Palo Alto) will likely enter or acquire their way in within 6–12 months. **Speed is the strategy.**

---

## 7. The Honest Competitive Sentence (Aug 23, 2026)

> Promptfoo now sells attack *and* defense — but as separate closed products, with the vendor grading its own homework. Garak and PyRIT attack but cannot measure a defense. NeMo and Model Armor defend but cannot prove it. Snyk scans configs but is closed-source and static. Augustus scans well but is scanner-only. DeepTeam simulates but doesn't execute. **Archon remains the only open platform where an adaptive attacker and a measurable defense fight in the same loop, with every verdict exported as evidence.**

---

## 8. Path to "World's Best" — the strategy in three sentences

1. **Own "measurable defense":** be the only platform where a CISO can point an adaptive attacker at their deployed guardrail config and hand auditors the trace as evidence — nobody else closes that loop.
2. **Meet enterprises where they are:** CLI-first CI integration, OTel-native telemetry, Postgres/Helm deployment, compliance-mapped reports — boring reliability features beat exotic attack research for deal flow.
3. **Out-open the incumbents:** Garak/Promptfoo proved communities form around plugin seams; Archon has five seams (attack/defense/provider/target/reporter) — make each one documented, versioned, and contribution-friendly before competitors copy the red/blue-loop category.

---

## 9. Recommendations / Priority Order (next 90 days)

**Hackathon (≤ Aug 31):** deploy Cloud Run via `DEPLOY_GCP.md`, record the 4-min demo (register → live battle → blocked trace in Cloud Trace → `archon battle --ci`), blog + `#AllThingsAgenticHackathon` post.

**Then (in this order):**
1. **Publish a live demo + docs** — one Docker + Postgres + Helm template, one YouTube walkthrough. Makes it usable, credible, enterprise-pilot-ready.
2. ~~AgentDojo / benchmark runner~~ — ✅ **DONE (Aug 23):** harness shipped, numbers published in [`RESULTS.md`](./RESULTS.md). Next: run with LLM layers enabled for the full-pipeline ASR.
3. ~~**Probe corpus 150+**~~ — ✅ **DONE (wave 7):** corpus 202, ahead of Garak's 195. Next frontier is LLM-driven attacker brains (GOAT/TAP/PAIR-class generation quality) on the provider seam.
4. **Attacker diversity** — providers beyond OpenAI-compat (local vLLM, Claude native) via the `LLMProvider` seam, benchmark-driven tuning.
5. **Ecosystem** — `contrib/` gallery, CI matrix for community pulls, plugin marketplace directory in README.
6. **Full-pipeline benchmark** — re-run AgentDojo with LLM layers enabled; publish end-to-end ASR next to deterministic-tier number.

Each is small, tested, and compounds: every one either adds users, adds proof, or closes a gap the incumbents still hold.

---

## 10. Corrections Log (vs. prior versions)

1. ❌ "Archon | Xiaomi" → Archon is independent (Yasir Raza).
2. ⚠️ Stale star counts updated: Promptfoo 22.4k→~24.5k, Garak 8.2k→~8.9k, PyRIT 4k→~4.3k.
3. ✅ "Promptfoo = OpenAI" retained — now *verified* against Promptfoo's README rather than assumed.
4. ➕ Added previously missing competitors: AgentDojo, NeMo Guardrails, Snyk Agent Scan/mcp-scan, Google Model Armor; commercial context (Lakera, Zenity, etc.).
5. 🧹 Removed unverifiable claims ("157 plugins" kept only with approximation framing; PyRIT coverage percentages dropped).
6. ✅ (Aug 23) "Garak primarily single-turn" → **corrected**: GOAT/TAP/Agent Breaker/Latent Injection verified in v0.16.1 source. Multi-turn is table stakes; the differentiator is the red/blue measurement loop.
7. ✅ (Aug 23) §5 scorecard reconciled with §5.1 — rows 7–10 zeros were a stale pre-ship snapshot; updated to shipped state (517 tests).
8. ➕ (Aug 23) Added DeepTeam/DeepEval/RAGAS to the landscape; added code-verified refresh §10.5.
9. ✅ (Aug 23, post-N3) Full refresh at 649 tests: §5 scorecard updated for the shipped post-hackathon sprint wave (sandbox battles, memory poisoning, ASI07 attacks, trace-driven generation, severity derivation, compare engine, Web UI, contrib gallery, distribution); new agentic scorecard §5.1 — Archon holds full coverage on all seven agentic dimensions; no competitor holds more than one partial.
10. ➕ (Aug 23) Added Augustus (Praetorian), Obot, Guardrails AI, NeuralTrust to the landscape based on web research.
11. ➕ (Aug 23) Added market size data ($769M→$2.1B by 2035) and M&A activity (Palo Alto/Protect AI, Snyk/Invariant Labs).
12. ✅ (Aug 24, post-waves 7–9) Refresh at 1,376 tests: corpus row now 202 probes (largest open agentic corpus); published-benchmark ladder added (AgentDojo deterministic + Tier-3 full-pipeline 27.2%, InjecAgent, strict-ASR 18.5%, per-target ground-truth 81.8%, pass^k, R-Judge judge-agreement 89.2% at human ceiling — no competitor publishes attempt-budget-disclosed numbers); ASI coverage now 10/10 full (ASI05 closed Aug 24 by targets/code_exec.py).

13. ✅ (Aug 25, post-wave-11) Competitor-mined completion wave: all 24 improvements shipped — SARIF 2.1.0 output (**category-first: no competitor emits SARIF**, unlocks GitHub Code Scanning), judge-calibration harness w/ Krippendorff α (productizes R-Judge one-off), fail-closed tool-call schema rail (NeMo IORails port), Policy Puppetry + token-smuggling converters (PyRIT ports), coding-agent target suite core-5 (promptfoo parity), SKILL.md scanning + `archon discover` (agent-scan parity), toxic-flow graph + E002 shadowing, buff layer (garak pattern), BEAST suffixes, streaming rolling-buffer rails, /v1/checks sidecar. Corpus 202→222; suite →1,941.

---

*Superseded historical analyses live in `docs/archive/` (`ALTERNATIVES_COMPARISON`, `RESEARCH_REPORT`, `PROJECT_REVIEW`, `plan`, `research`).*
