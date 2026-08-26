# ARCHON v3 BLUEPRINT — World-Class Agent Security Platform & Hackathon Victory Plan

> **Version:** 3.1 · **Date:** August 23, 2026 · **Branch:** `hackathon-v2` (`main` untouched)
> **Supersedes:** all previous blueprint versions. Competitor claims verified against live sources Aug 22–23, 2026 (see §9 Corrections Log). v3.1 adds: AgentDojo benchmark shipped with published ASR (`RESULTS.md`), probe corpus 53→72 with false-positive canaries, and code-verified competitor intel across 9 cloned repos (garak, promptfoo, PyRIT, NeMo Guardrails, AgentDojo, Snyk agent-scan, DeepTeam, DeepEval, RAGAS).

---

## 0. Document Map — How the Docs Fit Together

| Document | Role | Status |
|---|---|---|
| `README.md` | Product front door — what Archon is, how to run it | ✅ Updated v3 |
| `STATUS.md` | Single current-state snapshot (tests, capabilities, remaining work) | ✅ Added Aug 23 |
| `COMPETITIVE_ANALYSIS.md` | Verified competitor & market intelligence | ✅ Rewritten v3.1 (code-verified vs 9 repos) |
| `BLUEPRINT_HACKATHON.md` | This file — product architecture + competition strategy | ✅ Rewritten v3.1 |
| `RESULTS.md` | Published AgentDojo v1 benchmark numbers (ASR/block-rate) | ✅ New Aug 23 |
| `docs/LANDSCAPE_2026.md` | Master synthesis: market, protocols, research frontier, regulation, strategic bets | ✅ New Aug 23 |
| `REPORT_COMPARATIVE.md` | Current-state capability report vs competitors | ✅ Updated v3.1 |
| `ROADMAP.md` | Post-hackathon product roadmap (core-first) | ✅ Rewritten against shipped reality |
| `ARCHITECTURE.md` | Legacy competition-stack ADR (attacker/defender internals) | ⚠️ Historical annex — see §3 here for the v3 package architecture |
| `docs/archive/` | Superseded historical docs (`ALTERNATIVES_COMPARISON`, `PROJECT_REVIEW`, `RESEARCH_REPORT`, `plan`, `research`) | 🗄️ Archived Aug 23 |

**Reading order for judges/collaborators:** README → STATUS → COMPETITIVE_ANALYSIS → this file → RESULTS → ROADMAP.

---

## 1. Strategy in One Paragraph

Archon's core is already differentiated and proven (**2,093 passing tests**, CI-enforced, ranked 6th Defense in the Berkeley AgentBeats arena): an adaptive multi-turn attack engine (GOAT-style) and a budgeted multi-layer defense pipeline that no open-source competitor combines. The path to world-class is **not** more attack research — it is **productization**: extract the attack engine and defense pipeline into a provider-agnostic core library, ship the defense pipeline as a deployable runtime proxy (the one thing Garak/Promptfoo/PyRIT categorically don't do), wrap everything in extensible ABCs so new providers/targets/plugins bolt on without touching core, and treat hackathon integrations (Google ADK, Gemini, GCP, Cloud Run) as **optional adapters**, not architectural dependencies. Win the hackathon *because* the product is good, not by warping the product around the hackathon.

## 2. Verified Market Intelligence (as of Aug 22, 2026)

### 2.1 Open-source leaders (verified against cloned source code, Aug 22–23, 2026)

| Tool | Owner | Stars | License | What it actually does | Real weaknesses (honest, code-verified) |
|---|---|---|---|---|---|
| **Promptfoo** v0.122 | **Part of OpenAI** (per its own README; remains MIT) | ~24.5k | MIT | ~150 red-team plugins × ~35 strategies (incl. real MCP target provider driving live tool calls); OTel GenAI tracing; **9 compliance frameworks** (OWASP LLM/API/Agentic ASI01-10, MITRE ATLAS, NIST AI RMF, EU AI Act, ISO 42001, GDPR, DoD); code-scanning product | Adaptive multi-turn **brains (Hydra/Goblin/Crescendo) run in promptfoo's cloud** — OSS ships provider stubs (`goblin.ts`: "the provider and cloud task own the behavior"); guardrails are a paid cloud API client, not a self-hosted proxy; memory/RAG poisoning is simulated two-step, not live-store attacks; Node ≥22 only |
| **Garak** v0.16.1 | NVIDIA | ~8.9k | Apache-2.0 | 195 probes / 122 detectors / 45 generators / 7 buffs; named attacks: **GOAT** (O-T-S-R attacker loop), TAP×3, Latent Injection×8, **Agent Breaker** (tool-analyzing multi-turn), GCG, AutoDAN; strongest compliance tagging (OWASP LLM01-10, AVID export, MISP ~180 tags, CWE, DeMIS, LMRC) | Scanner only — **zero runtime defense**; no live tool-execution sandbox, no environment-state verification, no multi-agent; new Context-Aware Scanning (CAS) self-described as "experimental and incomplete" |
| **PyRIT** v1.1.0.dev | Microsoft | ~4.3k | MIT | Deepest attack orchestration: Crescendo/PAIR/TAP/SkeletonKey/ManyShot + ~90 converters + 94 jailbreak templates + 59 dataset loaders; scenario matrix builder; CentralMemory provenance; `pyrit_scan` CLI + CoPyRIT GUI | **No compliance mapping anywhere in code** (biggest gap); agent surface thin (XPIA workflow + ATR dataset only — no MCP orchestrator, no memory/RAG attacks); Azure-leaning deps |
| **NeMo Guardrails** v0.24.0.dev | NVIDIA | ~7.0k | Apache-2.0 | Runtime defense product: LLMRails (Colang) + experimental IORails validating proxy (OpenAI wire only); ~30 guard integrations; streaming tool-call rails fail-closed; `/v1/checks` sidecar | **Zero offensive testing — cannot validate its own guards**; zero compliance mapping (grep-confirmed); tool rails are schema-level only (no env-state verification); heavy third-party detection glue |
| **AgentDojo** v0.1.35 | ETH Zurich Spy Lab | ~762 | MIT | NeurIPS 2024 benchmark: 86 user + 27 injection tasks, ~108 tools, FunctionsRuntime sandboxed execution with DeepDiff env-state ground truth (best-in-class instrumented environments); only 4 defenses | Benchmark not product; 14 attack classes mostly static templates; single threat class (indirect injection); slow cadence (last commit Jun 2026) |
| **Snyk Agent Scan** v0.6 (ex mcp-scan) | Snyk | ~2.9k | Apache-2.0 | Supply-chain static scanning: discovers 13 agents, 15 risk indicators (0-1000), Toxic Flows combination analysis; unique Agent Guard hooks into Claude Code/Cursor/Codex | **Never executes attacks** — analysis is a closed Snyk-API black box; enforcement cloud-side; no OWASP mapping; closed to contributions |
| **DeepTeam** v1.0.9 | Confident AI | — | Apache-2.0 | 38 vulnerability classes / 124 sub-types (11 agentic), 27 attacks (5 multi-turn), ~56 judge metrics, 7 frameworks incl. OWASP ASI 2026; CVSS module; TraceScanner/CodeScanner | Everything flows through a text callback — **no live tool/MCP interception, no real store poisoning**; CVSS impact hardcoded MEDIUM; guards are DIY library calls, no proxy |
| **DeepEval** v4.1.10 / **RAGAS** v0.4.3 | Confident AI / vibrantlabsai | 13.9k / 12.8k | Apache-2.0 | Eval-only: ~56 quality metrics (agentic: TaskCompletion, ToolCorrectness, MCP×3) / ~36 RAG metrics + KG testset synthesis | Zero security dimension (red teaming split out to DeepTeam post-v3); RAGAS cadence stalled Feb 2026 |

### 2.2 Platforms & commercial context

- **Google Cloud Model Armor** — real GA service in Security Command Center: bidirectional prompt/response screening (jailbreak, prompt-injection, malicious URLs, PII, grounding), integrates with Vertex AI, Apigee, Agent Gateway, LangChain, MCP servers. It is simultaneously the category Archon's defense pipeline plays in **and** a named component of the hackathon's Fortified Enterprise Fleet track.
- **OWASP Agentic Security Initiative** — *Top 10 for Agentic Applications (2026)*, *State of Agentic AI Security & Governance*, secure-MCP guidance. Aligning Archon's threat taxonomy to OWASP's gives instant credibility and vocabulary judges recognize.
- Commercial vendors (Lakera Guard/Red, Zenity, HiddenLayer, Mindgard, Haize Labs, Protect AI→Palo Alto Networks) validate enterprise budgets but none ship an open, self-hostable red/blue testing loop.

### 2.3 The structural gap nobody fills

Buyers must currently stitch ≥3 tools: a scanner (Garak/Promptfoo) for pre-deployment probes, an orchestration library (PyRIT) for campaigns, and a separate runtime guardrail (Model Armor / LLM Guard / NeMo) whose effectiveness they can never *measure*. **The unclaimed position: one platform where attack, defense, and observability meet — point Archon's attacker at Archon's (or anyone's) defense and get evidence, not vibes.**

Three artifacts required — none of the competitors have all three:
1. Multi-turn stateful attack engine with deterministic signal extraction ✅ *(exists today)*
2. Defense pipeline packaged as a drop-in runtime proxy with per-layer telemetry ✅ *(shipped: archon-armor)*
3. Extensible core where third parties add strategies/layers/providers via stable ABCs ✅ *(shipped: five seams + community pack loader)*

### 2.4 The nine gaps NO competitor covers well (code-verified across 9 repos, Aug 23, 2026)

This is Archon's opportunity space — each row was verified absent-or-weak in every cloned repo:

1. **Closed-loop verified security** — attack → deploy shield → re-attack to *prove* the shield works. garak/promptfoo/PyRIT are test-time only; NeMo defends but cannot self-validate; Archon's `BattleManager` + Policy-CI baselines do this today.
2. **Self-hosted runtime enforcement proxy** — promptfoo Guardrails is a paid cloud client; Snyk enforcement is a cloud black box; NeMo's IORails is closest but has zero offense and zero compliance mapping; archon-armor is an MIT OpenAI-compat proxy.
3. **Live tool-execution attacks in instrumented sandboxes** — ✅ **SHIPPED (Aug 23, 2026)**: `targets/sandbox.py` gives BranchingAttacker real tool-executing targets with ground-truth env-diff verification (`raw["attack_success"]`), plus closed-loop defended/undefended battles. AgentDojo has environments but static templates + 4 defenses; DeepTeam/promptfoo simulate via text callbacks; PyRIT has none.
4. ~~**Live memory/vector-store poisoning** — everyone simulates (promptfoo's `agentic:memory-poisoning` is a two-step scenario); nobody manipulates real stores.~~ **SHIPPED** — `targets/memory.py` plants real poison entries in a live store; a benign user query retrieves them and the vulnerable RAG target obeys (request-side pipeline provably can't see it); closed-loop remediation scrubbing verified.
5. ~~**Multi-agent trust-boundary attacks** — OWASP ASI07 is mapped by promptfoo but not attacked; DeepTeam covers it as a metric only.~~ **SHIPPED** (`targets/multiagent.py`: TrustBoundaryTarget — coordinator sanitizes direct input but trusts worker output; smuggled directives cross the boundary and leak secrets; sanitize_boundary=True is the defense variant).
6. **Compliance-mapped red teaming WITH exploitation** — promptfoo maps 9 frameworks but its adaptive brains are cloud-proprietary; PyRIT exploits deeply but has zero compliance mapping. Nobody combines both openly.
7. ~~**True CVSS derivation**~~ — ✅ SHIPPED: `reporting/severity.py` derives 0–10 scores from battle evidence (DeepTeam's impact score is hardcoded MEDIUM).
8. ~~**Trace-driven ATTACK generation**~~ — ✅ **SHIPPED (Aug 23, 2026)**: `attacks/trace_driven.py` mines JsonlTracer/OTLP-JSON spans into a `TraceProfile` and synthesizes targeted attacks (per-layer evasion, tool-targeted injection, error-exploit). promptfoo/DeepEval use traces for evaluation only; Archon attacks from them.
9. **MIT-neutral vendor independence** — post-OpenAI-acquisition, "vendor grades its own homework" is a real enterprise buying objection that only an independent MIT project answers.

## 3. Core-First Product Architecture (No Hackathon Lock-In)

### 3.1 Package layout

```
archon/
├── packages/
│   ├── archon-core/            # Pure library. Zero vendor deps. Importable anywhere.
│   │   ├── attacks/            # AttackStrategy implementations (GOAT, probes, chaining)
│   │   ├── defenses/           # DefenseLayer implementations (normalization → classifier)
│   │   ├── engine/             # BattleEngine, RoundScheduler, SignalExtractor
│   │   ├── scoring/            # Scorer impls: leak detection, tone, helpfulness
│   │   └── reporting/          # Reporter impls: JSON, HTML/MD battle reports
│   ├── archon-providers/       # LLMProvider ABC → OpenAI-compat, Anthropic, Gemini, local/vLLM
│   ├── archon-targets/         # TargetAdapter ABC → HTTP agent, A2A agent, MCP server, OpenAI-compat proxy
│   ├── archon-armor/           # THE deployable artifact: FastAPI defense proxy (/v1/chat/completions)
│   └── archon-cli/             # Typer CLI: archon run | scan | armor | report | list
├── integrations/               # Optional adapters — safe to delete, core never imports them
│   ├── gcp/                    # Cloud Run manifests, Firestore registry backend, Pub/Sub queue
│   ├── google-adk/             # ADK target adapter + Gemini provider (hackathon demo path)
│   └── otel/                   # OpenTelemetry span exporter (works with any collector)
├── scenarios/security_arena/   # Existing competition plugins (compat layer over archon-core)
└── src/agentbeats/             # Legacy competition harness (frozen; compat only)
```

**Dependency rule (enforced by import-linter):** `integrations/*` and `scenarios/*` may import `packages/*`; nothing inside `packages/*` may import `integrations/*`, cloud SDKs, or A2A. This is what "core-first" means mechanically.

### 3.2 The five extension seams (stable ABCs)

Every axis of growth is a single interface third parties implement without touching core:

```python
# attacks/base.py
class AttackStrategy(ABC):
    """A stateful multi-turn attack campaign."""
    name: str
    surfaces: frozenset[AttackSurface]      # direct / indirect-injection / tool / memory / output
    @abstractmethod
    async def next_payload(self, ctx: BattleContext) -> AttackPayload: ...
    def observe(self, signal: RoundSignal) -> None: ...   # hook: adapt after each round

# defenses/base.py
class DefenseLayer(ABC):
    """One stage of the request/response pipeline."""
    name: str
    llm_budget: int = 0                      # cost accounting is first-class
    @abstractmethod
    async def process(self, exchange: Exchange) -> Exchange: ...

# providers/base.py
class Provider(ABC):
    @abstractmethod
    async def generate(self, messages: list[Message], **kw) -> Completion: ...

# targets/base.py
class TargetAdapter(ABC):
    """Anything that speaks like an agent can be tested."""
    @abstractmethod
    async def send(self, payload: str) -> TargetResponse: ...
    # impls: HTTPTarget, A2ATarget, MCPTarget, OpenAICompatProxyTarget

# reporting/base.py
class Reporter(ABC):
    @abstractmethod
    async def emit(self, result: BattleResult) -> None: ...
```

Existing code maps onto these with ~80% reuse: `goat_loop.py` + `strategy_router.py` + `diagnosis.py` implement `AttackStrategy`; `normalization.py`, `threat_classifier.py`, `segmenter.py`, `pyrit_defense.py`, `execution_modes.py`, `output_guardrails.py` each become a `DefenseLayer`; `plugins/base.ScenarioPlugin` stays as the scenario seam.

### 3.3 archon-armor — the flagship artifact

The existing defender modules wrapped in a standalone **OpenAI-compatible FastAPI proxy**:

```
agent ──► POST /v1/chat/completions ──► [L0 normalize] ──► [L1 classify]
              │                                              │
              ▼                                              ▼
        X-Agent-ID header ──► Registry lookup (policy)   [L2 spotlight] ──► upstream LLM ──► [L3 shield] ──► [L4 classifier] ──► response
```

- Any agent built on any framework gets protected by changing one env var (`OPENAI_BASE_URL=...`).
- Every layer emits OTel spans + a per-exchange verdict → **defense effectiveness becomes measurable**, which is exactly what Model Armor/LLM Guard users cannot do today.
- Works identically against third-party defenses: point `TargetAdapter=OpenAICompatProxyTarget` at any guardrail endpoint and attack *it*.

## 4. Honest Gap Analysis — What Stands Between Archon and World-Class

| # | Gap | Severity | Evidence | Closure path |
|---|---|---|---|---|
| 1 | **Defense pipeline is not a product** — logic lives inside a competition agent, no standalone service | 🔴 Critical | `defender/pyrit_defense.py` has no server wrapper | `archon-armor` proxy (§3.3) |
| 2 | **Single-provider lock-in** — hardcoded OpenAI-compatible endpoint | 🔴 High | `pyproject.toml`, scenario TOMLs | `Provider` ABC (§3.2) |
| 3 | **No CLI/config surface** — TOML competition runner only; no YAML/JSON config, no exit codes for CI | 🔴 High | `src/agentbeats/run_scenario.py` | `archon-cli` + declarative config |
| 4 | **No observability** — battle logs are ad-hoc JSON, not spans/metrics | 🟠 Medium | orchestrator logging | `integrations/otel` |
| 5 | **Thin probe corpus** vs Garak's probe library / Promptfoo's plugin count | 🟠 Medium | 7 strategy families | Port top OWASP-LLM & AgentDojo attack classes as `AttackStrategy`s; community seam makes this crowd-solvable |
| 6 | **No MCP/tool-surface testing** — the hottest agentic threat class (tool poisoning per OWASP Agentic Top-10) untested | 🟠 Medium | no MCP adapter | `MCPTarget` adapter + tool-poisoning strategies (post-hackathon) |
| 7 | **No registry/identity** | 🟡 Low (product) / 🔴 High (hackathon track) | absent | Registry ABC w/ SQLite core impl + Firestore integration impl |
| 8 | **Packaging/docs/community** — not pip-installable as a tool, repo named `arcon` | 🟠 Medium | pyproject targets only `agentbeats-run` | rename repo, restructure packages, docs site |
| 9 | **No benchmark credibility** — AgentDojo/HarmBench numbers are how researchers compare tools | 🟡 Low | absent | run Archon attacker against AgentDojo suites post-hackathon |
| 10 | ~~**Engineering maturity**~~ — ✅ CLOSED (waves 1–5): CI matrix + coverage gate live, MIT/v1.0.0 identity + cosign SBOM releases, competition deps isolated, migrations + results store, SECURITY.md threat model + nonce-store replay protection | ~~🔴 High (post-hackathon)~~ | Aug 25, 2026 | Phase E2.11 competitor-mined completion wave SHIPPED (waves 11A+11B, 9 parallel TDD subagents + orchestrator): Tier-1 — fail-closed tool-call schema rail (NeMo IORails port), Policy Puppetry + token-smuggling converters (PyRIT ports), SHIFT_DETECTED early-stop wired into crescendo/adaptive (deepteam port), ensemble score aggregation, hidden-Unicode Cf/Cc scanner w/ U+E0000 tag decoding (agent-scan W021), deterministic agent-loop trace metric (deepeval port), typed MetricOutputType judge contract + kappa agreement (ragas port), harm-taxonomy YAML layer (12 defs × 5-level rubrics), /v1/checks sidecar endpoint (NeMo adoption unlock), ANSI escape exfil + package-hallucination probe packs; Tier-2/3 — SARIF 2.1.0 output (category-first: no competitor emits it), self-contained HTML report, `archon discover` local-config discovery, SKILL.md supply-chain scanning, buff layer (garak pattern), judge-calibration harness (accuracy/F1/kappa vs human labels), run-history experiment store w/ diffs, toxic-flow capability graph + E002 shadowing, coding-agent target suite core-5 (verifier-sabotage/CI-poisoning/procfs-read/egress-bypass/tty-injection), streaming rolling-buffer rails, BEAST-style deterministic suffix attacker, compliance-card renderer. Corpus 202→222. Suite 1485→1868 (+383 TDD tests), ruff clean | ✅ Done | `defenses/tool_rail.py`, `attacks/{policy_puppetry,token_smuggling,progression,buffs,beast}.py`, `security/{aggregation,unicode_scan,skill_scan,toxic_flows}.py`, `reporting/{loop_metric,metric_contract,harm_taxonomy,judge_calibration,sarif}.py`, `targets/coding_agent.py`, `discovery/clients.py`, `archon_armor/{html_report,run_history,report_cards,streaming}.py` |
| Aug-23 audit verdict B+/C+ — every named gap closed by Phase E0/E2.6 (see ROADMAP gap table) | Done |

> **Post-hackathon strategy note (Aug 23):** the [`LANDSCAPE_2026.md`](./docs/LANDSCAPE_2026.md)
> research adds a maturity thesis — *enterprises buy operational maturity; researchers buy
> capability* — plus five research-derived differentiators (adaptive multi-attempt methodology,
> UAR/PED metrics, MCP/A2A protocol-layer inspection, compliance evidence automation,
> AIUC-1/CSA STAR certification alignment) scoped as Phase E2.5 in ROADMAP v5.1.

## 5. The Hackathon Layer (All Things Agentic — deadline Aug 31, 5:00pm PDT)

### 5.1 Verified competition facts

- **Tracks/prizes:** Grand Prize $50K · *The Fortified Enterprise Fleet* $20K (Archon's track) · plus Taskmaster/Collaborative Partner/Startup/Individual/Architecture/Multimodal tracks.
- **Judging:** Innovation & Operational Utility **40%** · Architectural Discipline & Tech Stack **30%** · Demo & Production Readiness **30%**.
- **Hard expectations:** built on Gemini / Google ADK / Google Cloud; visible proof of GCP deployment; public demo video (unedited); architecture diagram; reproducible setup.
- **Bonus points:** blog post on a public platform stating it was created for this hackathon; social post with `#AllThingsAgenticHackathon`; integrate Gemma/Veo/Lyria.
- **Time remaining from Aug 22: ~9 days.**

### 5.2 How the core maps onto the Fortified Enterprise Fleet spec

| Track requirement | Archon answer | Core or integration? |
|---|---|---|
| Agent Runtime (async background execution) | BattleEngine runs battles async; Cloud Run Jobs wrapper | Core + `integrations/gcp` |
| Memory Bank (cross-session context) | Battle state persistence; pluggable store (SQLite → Firestore) | Core + integration backend |
| Agent Identity (zero-trust access) | `X-Agent-ID` + registry policy lookup in archon-armor | Core interface, GCP IAM impl optional |
| Agent Gateway (policy enforcement) | archon-armor **is** the gateway | Core artifact |
| Model Armor (prompt injection/tool poisoning/PII) | Defense layers L0–L4 + output guardrails; name-checked alignment with Google's service | Core artifact |
| Agent Observability (OTel audit logs/reasoning traces) | Per-layer OTel spans exported to Cloud Trace | `integrations/otel` + GCP exporter |
| Agent Registry (discovery/versioning) | Registry ABC; SQLite default, Firestore for demo | Core + integration |

**Every track requirement is satisfied by a core module with an optional GCP implementation behind it.** Nothing in core knows Google exists.

### 5.3 9-day execution plan (rubric-mapped)

| Days | Deliverable | Rubric points served | Notes |
|---|---|---|---|
| 1–3 | **archon-armor**: FastAPI `/v1/chat/completions` proxy wrapping L0–L4; Dockerfile; deploy to Cloud Run | Demo/Production 30% + Gateway + Model Armor requirements | Highest ROI item; defender modules are pure functions — this is packaging, not research |
| 3–4 | **Registry MVP** (`Registry` ABC, SQLite impl, agent cards + security policy); identity header enforcement | Architectural Discipline 30% | Half-day if scoped tightly |
| 5–6 | **Observability**: OTel spans per battle round (attack technique → each defense layer → verdict), export to Cloud Trace | Innovation 40% (measurable defense = the novel claim) + observability requirement | Deterministic signal extraction maps perfectly to span attributes |
| 6–7 | **Google proof path**: Gemini provider adapter; one ADK target adapter; flagship battle attacker=Gemini, defender=armor proxy; paraphrase layer on **Gemma** (bonus checkbox) | Tech stack 30% + Gemma bonus | This is the demo storyline backbone |
| 7–8 | Async orchestration polish: submit-battle/poll-status API on Cloud Run (background tasks, **not** Pub/Sub+Redis — descope) | Runtime/memory requirements | |
| 8 | **Demo video** (≤4 min, unedited): register agent → armor protects live agent → GOAT attacker blocked layer-by-layer in Cloud Trace → helpfulness intact (normal-user test) | Demo 30%, the single highest-leverage artifact | Script it day 7 |
| 9 | Submission package: architecture diagram, README rewrite, description, GCP screenshots, blog post + `#AllThingsAgenticHackathon` post (both are literal bonus criteria) | Bonus + polish | |

**Explicitly descoped:** multi-agent swarm attacks, RL-adaptive strategies, web UI, plugin marketplace. None are rubric-critical; all are ROADMAP items.

## 6. Positioning — The One-Liner (Truth-Checked)

> **Garak scans models. Promptfoo asserts configs. PyRIT scripts attacks. Archon is the only open platform where an adaptive multi-turn attacker and a production-grade, measurable defense pipeline fight in the same loop — and the defense ships as a drop-in proxy any agent can use.**

Supporting claims are deliberately conservative because judges and HN readers check:
- ✅ "Promptfoo is part of OpenAI" — verified via Promptfoo's own README.
- ✅ "PyRIT works with any endpoint" — verified; do **not** claim it's Azure-locked.
- ✅ "Garak is primarily single-turn" — accurate framing; don't overclaim "no multi-turn at all".
- ❌ Never claim "nobody does X" without checking AgentDojo (which *does* evaluate defenses) or Model Armor (which *does* filter prompts). Our differentiator is the **combination + runtime measurability**, stated above.

## 7. Submission Checklist

- [ ] Public repo clean: `main` stable, `hackathon-v2` merged or clearly linked; rename GitHub repo `arcon` → `archon`
- [ ] Demo video ≤4 min, unedited, public (YouTube), mentions hackathon
- [ ] Architecture diagram (core packages + integrations ring)
- [ ] GCP proof: Cloud Run service URLs, Cloud Trace screenshot of a defense-pipeline trace, Firestore/registry screenshot
- [ ] 500–1000 word Devpost description using OWASP Agentic terminology
- [ ] Blog post (dev.to/Medium): "created for the All Things Agentic Hackathon"
- [ ] Social post with #AllThingsAgenticHackathon
- [ ] Gemma integration noted in README + demo

## 8. Post-Hackathon Trajectory (summary — details in ROADMAP.md)

1. **v0.2:** pip-installable `archon` CLI, YAML config, CI exit codes → compete for Promptfoo's security niche. ✅ *Shipped Aug 22.*
2. **v0.3:** MCP target adapter + tool-poisoning attack suite → own the OWASP Agentic Top-10 conversation before Snyk Agent Scan's static-only approach can follow. ✅ *Shipped Aug 22 (static scan + live behavioral probing).*
3. **v0.4:** AgentDojo benchmark integration + published results → researcher credibility. ✅ *Shipped Aug 23 — `archon_benchmarks` + `RESULTS.md` (81 attacks over all 27 published v1 injection tasks; deterministic-tier ASR 66.7%).*
4. **v1.0:** registry server, multi-tenant armor deployments, OTel-native everywhere. 🚧 *Postgres registry + Helm + OTLP→Cloud Trace shipped; multi-tenant control plane remains.*

## 9. Corrections Log — False/Stale Claims Removed in v3

| Prior claim | Status | Correction |
|---|---|---|
| "Archon \| Xiaomi" (COMPETITIVE_ANALYSIS §1.1) | ❌ False | Archon is an independent project by Yasir Raza; no corporate owner |
| "PyRIT is Azure-locked" | ❌ Overstated/false | PyRIT is MIT-licensed, endpoint-agnostic; Azure targets are optional. Repo moved to `microsoft/PyRIT` |
| "PyRIT 40% agent validation coverage" | ❌ Unverifiable | Removed — no public source supports a precise figure |
| "Garak 8.2k stars / 80+ probes" | ⚠️ Stale | ~8.9k stars; probe count kept approximate ("80+") |
| "Promptfoo acquired by OpenAI (neutrality dead)" | ✅ Verified TRUE | Confirmed by Promptfoo README ("now part of OpenAI", still MIT). Tone softened: neutrality concern noted as market context, not a "fatal flaw" |
| "Today is Aug 18, you have 14 days" | ⚠️ Stale | Deadline Aug 31, 2026 5:00pm PDT → ~9 days from Aug 22 |
| Blueprint's GCP-first build order (Pub/Sub+Redis+Firestore on days 1–2) | ⚠️ Reordered | Core-first: ship archon-armor + registry MVP first; cloud infra behind optional adapters; Pub/Sub/Redis descoped |
| "LLM Guard (Protect AI)" | ⚠️ Context added | Protect AI was acquired by Palo Alto Networks (2025) |
| mcp-scan (Invariant Labs) missing entirely | ⚠️ Added | Now Snyk Agent Scan (~2.9k★); static MCP/skills scanner |
| "Garak GOAT probe unverified — do not use publicly" (SOTA_STRATEGY Shift 3) | ✅ Verified in code Aug 23 | `garak/probes/goat.py` exists in v0.16.1.pre1: O-T-S-R attacker-LLM loop; also `agent_breaker.py` (tool-analyzing multi-turn), TAP×3, Latent Injection×8. Garak is **not** single-turn anymore |
| "Promptfoo Hydra/Goblin/Crescendo run locally" | ❌ False (code-verified) | Multi-turn strategy brains live in promptfoo's cloud; OSS ships provider stubs (`goblin.ts` admits it). OSS without connectivity loses adaptive coverage |
| "DeepTeam CVSS scoring" | ⚠️ Weak (code-verified) | Impact component hardcoded `DEFAULT_IMPACT = MEDIUM` — not derived from vulnerability type |
| "PyRIT has compliance mapping" | ❌ False (grep-verified) | Zero OWASP/NIST/MITRE mapping anywhere in PyRIT code — its biggest enterprise gap |
| "NeMo Guardrails has no runtime product" | ❌ Corrected | It IS a runtime defense product (IORails validating proxy, `/v1/checks`, streaming tool-call rails) — but with zero offensive self-testing and zero compliance mapping |

---

*End of BLUEPRINT v3. Maintain this document alongside code changes on `hackathon-v2`; bump version and date on every substantive edit.*

---

## 10. Implementation Progress Log

| Date | Phase | Status | Evidence |
| Aug 25, 2026 | Phase E4 SHIPPED (wave 13, 12 parallel TDD subagents, +202 tests → **2,295 passed / 3 skipped**): universal benchmark coverage — XSTest (0.0% over/under-refusal), Agent-SafetyBench, BIPIA, IPIArena (**official artifact** via PIMiner repo), ASB (**official** agiresearch/ASB), HarmBench-full 400 behaviors (framed 100% blocked vs direct 0%), AgentHarm, StrongREJECT (+env-gated rubric judge), MCPTox-style wrapper (100% static detection), tau-bench policy-probe loader, WASP dual-ASR tagging layer, SkillTrustBench validator. All cache→network→fixture reproducible; deterministic-tier numbers published in RESULTS.md | ✅ Done | `archon_benchmarks/{skilltrust,xstest,asb_safety,bipia,agentharm,harmbench_full,wasp_tags,strongreject,ipiarena,asb,mcptox,taubench}.py` + fixtures |
| Aug 25, 2026 | Phase E4 PLANNED — universal benchmark coverage (wave 13): every benchmark competitors and papers use, reproducible in-repo (cache→network→fixture, deterministic-first, LLM tiers env-gated): SkillTrustBench, XSTest, Agent-SafetyBench, BIPIA, AgentHarm, HarmBench-full, WASP dual-ASR tagging, StrongREJECT, IPIArena, ASB, MCPTox wrapper, tau-bench loader | ✅ Planned → shipped same day | ROADMAP E4 items 73–84 |
| Aug 26, 2026 | Phase E5 SHIPPED (wave 14, 14 parallel TDD sprints, +166 tests → **2,484 passed / 3 skipped**, ruff clean): Tier 1 — ActionReminderLayer+ToolRail wired into _build_request_pipeline (enforced per-request), harness ergonomics (on_progress/incremental saves/response sampling), DEFAULT_TIMEOUT_SECONDS=300 w/ env override, property tags in Battle.finalize, harm-weighted severity vectors, compliance cards in HTML report, security/approval.py C3 ContextBinding + C4 ed25519 ApprovalToken, buffed_series multiplicative coverage. Tier 2 — security/flow_policy.py (AgentFlow labels+flow rules+path operators, no SMT), defenses/agri.py (latent-signal probe-gated defense, vLLM-only self-documented), strategies/ 7 PIMiner seed cards + StrategyLibrary.load_dir, benchmarks/matrix_runner.py, taubench run_taubench_usersim env-gated LLM user loop, discover --scan-skills + packaging/uvx.md | ✅ Done | flow_policy.py, agri.py, approval.py, strategies/, matrix_runner.py, buffed_series.py |
| Aug 26, 2026 | Phase E5 PLANNED — Integration & frontier completion (wave 14): Tier 1 pre-deadline (pipeline wiring of ActionReminderLayer+ToolRail, harness ergonomics/resumability/sampling, timeout fix, property-tagged summaries, harm-weighted severity, HTML compliance cards, APC C3/C4, buff-layer series) + Tier 2 frontier (AgentFlow path-rules YAML subset, AGRI opt-in vLLM module, PIMiner strategy seeding, multi-provider matrix runner, tau-bench user-sim, discover→skill-scan+uvx). ROADMAP items 85–98 | ✅ Planned | ROADMAP E5, STATUS checklist |
| Aug 25, 2026 | Phase E3 SHIPPED (wave 12, 7 parallel TDD subagents + orchestrator, +147 tests → **2,093 passed / 3 skipped**): PiminerBrainAttacker (hierarchical memory: RunMemory Curate 20K cap + StrategyLibrary markdown + LLM router Top-K=3 + Digester 3-way classify), ActionReminderLayer (action-time policy reminder w/ replay_with_placebo 3-arm protocol, REDAgentBench −74.19pp evidence), property_tags.py (SA/TA/AA/DI classification per arXiv:2607.22024), StepJackTarget deterministic CUA page-chain target + fixture loader (32 tests), caveats.py composition closure (prohibit_pair/prohibit_tuple + SessionActionRegistry + Blast Radius Monotonicity property test), skill_scan lifecycle stages (manifest consistency / Sybil clustering @0.85 Jaccard / version-diff escalation), prompt_as_rule.py LLM audit tier (10 OWASP-MCP-aligned rules w/ mandatory exclusions + untrusted-artifact delimitation). Wave-12 ground-truth benchmark series published: mean ASR 66.7% across 6 new targets (StepJack chain 100%, DNS rebinding/off-path/sandbox-escape/sleeper 66.7%, destructive 33.3% — sub-100% = payload-format sensitivity of mutation variants vs format-sensitive parsers, not defense) | ✅ Done | `attacks/piminer.py`, `defenses/action_reminder.py`, `reporting/property_tags.py`, `targets/cua.py`, `security/{caveats,skill_scan,prompt_as_rule}.py`, `archon_benchmarks/wave12_series.py` |
| Aug 25, 2026 | Phase E3 PLANNED — Research-derived frontier (wave 12): 12-paper deep read (arXiv-verified, corrections applied to new_research.md) yields 7 implementable items: PIMiner hierarchical-memory attacker upgrade (+17.8–19.8 pts), action-time policy reminder DefenseLayer (−74.19pp REDAgentBench evidence), SA/TA/AA/DI property-tagged metrics (arXiv:2607.22024), StepJack deterministic CUA target (GPL dataset), APC composition-closure caveats C2b, skill-scan Storage/Retrieval/Evolution stages, Prompt-as-Rule LLM audit tier. ROADMAP items 66–72 | ✅ Planned → shipped same day | ROADMAP E3, STATUS checklist |
| Aug 24, 2026 | Phase E2.11 PLANNED — Competitor-mined completion wave: three-way improvement mining across promptfoo/augustus/agent-scan (DX/product), garak/PyRIT (attacks), NeMo/deepeval/deepteam/ragas (defense/eval) yielded 24 candidates: Tier 1 quick wins ×12 (tool-call schema rail, Policy Puppetry, token smuggling, SHIFT_DETECTED early-stop, /v1/checks sidecar, ensemble aggregation, ANSI exfil, hidden-unicode scanner, agent-loop metric, MetricOutputType contract, package-hallucination probes, harm-taxonomy layer), Tier 2 ×8 (SARIF ⭐ category-first, static HTML report, archon discover, skill scanning, buff layer, judge-calibration harness, run-history diffs, toxic-flow graph), Tier 3 ×4 (coding-agent suite, streaming rails, BEAST suffixes, compliance cards). ROADMAP items 66–89 | 🔜 Planned → parallel TDD next | ROADMAP E2.11, STATUS checklist |
| Aug 24, 2026 | Phase E2.10 Augustus-derived hardening SHIPPED (wave 10, 3 parallel TDD subagents + orchestrator): MCP transport-layer attack targets (DNS-rebinding TOCTOU / session-hijack / off-path credential-exfil, each w/ paired defense + state-diff ground truth), Prometheus /metrics endpoint on archon-armor (ArmorMetrics stdlib collector wired into create_app), YAML declarative probe packs (Nuclei-style community format), AI code-review PR workflow, secrets-scan + verify-pins supply-chain workflows. Suite 1421→1485 (+64 TDD tests), ruff clean | ✅ Done | `targets/mcp_transport.py`, `archon_armor/{metrics,yaml_packs}.py`, `contrib/yaml/example_pack.yaml`, `.github/workflows/{ai-review,secrets-scan,verify-pins}.yml` |
| Aug 24, 2026 | Phase E2.10 PLANNED — Augustus-derived hardening (wave 10): deep engineering comparison vs praetorian-inc/augustus (cloned; 201K Go LOC, 4,057 test funcs, 13 CI workflows, network-level MCP transport attacks — strongest offense-only rival) identified 5 adopt-worthy ideas: MCP transport-layer attack target (DNS rebinding/session hijack/off-path attacker, closed-loop verified), AI code-review CI workflow, Prometheus /metrics on archon-armor, YAML declarative probe packs, supply-chain CI hygiene (secrets-scan + verify-pins). ROADMAP items 61–65 | 🔜 Planned → shipped same day | ROADMAP E2.10, STATUS checklist |
| Aug 24, 2026 | FinBot CTF sim extended to **7 challenge-grounded vectors** (19 TDD tests): each new vector mirrors a real YAML challenge definition from the clone — rce-shell-shock (foot-in-the-door RCE: malicious script executes only after prior safe maintenance interactions, single-shot refused), destructive-scorched-earth (poisoned manage_storage description turns any later storage workflow into a total FinDrive wipe), recon-onboarding (profile-field injection disclosing internal trust/risk decision rules), policy-bypass-gradual-status-flip (prohibited vendor reaches active only via intermediate transitions); FinBotDefense pre-screens all four; closed-loop BranchingAttacker succeeds-vs-vulnerable / fails-vs-defended. Suite 1402→1421 | ✅ Done | `targets/finbot.py`, `tests/armor/test_finbot_challenges.py` |
| Aug 24, 2026 | ASI05 CLOSED — OWASP Agentic Top-10 now **10/10 full**. New `targets/code_exec.py` battle suite (26 TDD tests): SleeperAgentTarget (persistent payload → privileged backend read → execution, modeled on FinBot CTF rce/sleeper_agent), SandboxEscapeTarget (os.system/subprocess/__import__/workspace-path escape vectors), DestructiveCommandTarget (mass purge without approval, FinBot scorched_earth pattern); paired defenses (write-time quarantine, command allowlist, approval gate) close the loop via BranchingAttacker. Suite 1376→1402 | ✅ Done | `targets/code_exec.py`, STATUS/ROADMAP/COMPETITIVE_ANALYSIS ASI rows |
| Aug 24, 2026 | R-Judge LIVE LLM-JUDGED RUN PUBLISHED — full 571-record corpus judged by gemini-3.1-flash-lite through Archon's declared-judge harness (paced, resumable driver): **accuracy 89.2% / F1(unsafe) 0.893** (precision .917 / recall .870) — at the human-agreement ceiling (89.07%) and far above GPT-4o's published 74.4% F1; heuristic floor was 47.6%/F1 0.063. Ops notes: per-model RPD buckets (switched lite models mid-run), ARCHON_ATTACK_PROVIDER_API_KEY env gotcha documented | ✅ Done | RESULTS.md R-Judge LLM-judge row + methodology block; commit 39ebb49 |
| Aug 24, 2026 | Phase E2.9 external benchmark expansion SHIPPED (wave 9, 4 parallel TDD subagents): InjecAgent harness — full 1,054-case corpus (510 direct-harm + 544 data-stealing), deterministic tier blocks 0%/ASR 100% (polite imperatives inside JSON tool output carry no override keywords — empirical case for LLM layers); tau-bench pass^k consistency — 11/11 targets pass^k=1.0 across seeds 42/43/44 (structurally exploitable, seed-insensitive); R-Judge harness w/ pluggable judge (heuristic agreement run: n=571, acc 47.6%, F1_unsafe 0.063 — quantifies rule-judging failure); WASP dual-ASR formal labeling + NIST CAISI methodology-alignment citations in RESULTS.md; OpenRouter + NVIDIA NIM provider presets in provider_from_env. Suite 1321→1376 (+55 TDD tests), ruff clean | ✅ Done | `benchmarks/{injecagent,passk,rjudge}.py`, `providers/__init__.py`, RESULTS.md ×4 sections; suite 1376 |
| Aug 24, 2026 | Wave 8 — ALL remaining key-unlocked gaps CLOSED (4 parallel TDD subagents + orchestrator live runs): (A) LlmBrainAttacker GOAT-style O-T-S-R brain on provider seam w/ graceful degradation + live validation (0/3 @ budget 4 vs gemini-3.5-flash-lite — honest floor, confirms strict-ASR finding); (B) strict_asr.py strict-ASR benchmark PUBLISHED: evasion 100% vs **strict ASR 18.5%** (5/27 tasks, median 3 attempts-to-compliance, 74/135 upstream calls) — evasion ≠ compromise quantified; (C) vLLM provider path (VllmProvider preset, local-models.md, schema-valid example); (D) editor DX (.vscode schema wiring). garak/PyRIT brain+orchestration rows now ✅ closed. Suite 1260→1321 (+61 TDD tests), ruff clean | ✅ Done | `attacks/llm_brain.py`, `benchmarks/strict_asr.py`, `providers/vllm.py`, RESULTS.md ×2 sections, .vscode/, docs-site/local-models.md; suite 1321 |
| Aug 24, 2026 | Tier-3 FULL-PIPELINE BENCHMARK PUBLISHED — first live-upstream run (user-supplied Gemini key, `gemini-3.5-flash-lite` @ free-tier 15 RPM throttle): 81 attacks → 27 blocked pre-upstream (33.3%), 54 reached the model, 22 complied → **full-pipeline ASR 27.2%** vs deterministic-tier 66.7%; defense-in-depth measured: free deterministic tier + model-native safety cuts successful attacks by ~60% at zero defensive LLM spend; residual 27.2% = exactly what Archon's LLM defense layers target. Fixed real bug found on first live run: llm_tier per-probe asyncio.run() closed the loop under httpx AsyncClient ('Event loop is closed' on call #3) — refactored to single-event-loop body + regression test (+1). Suite 1259→1260 | ✅ Done | RESULTS.md Tier-3 section, `llm_tier.py` refactor, tests/benchmarks/test_benchmark_tiers.py; suite 1260 |
| Aug 24, 2026 | Phase E2.8 evidence & hardening sprint SHIPPED (wave 7, 10 parallel TDD subagents + orchestrator): (45) per-target ground-truth benchmark series — `target_series.py`, adaptive attacker (budget 3, seed 42) vs all 11 live targets, aggregate ASR **81.8%** (27/33) from state-diff ground truth w/ zero LLM calls, published in RESULTS.md; (46) false-positive rate — **0/12** benign canaries blocked (0.0% over-refusal), methodology commitment #4 closed; (47) applied-metrics exemplar — UAR 0.75 / PED 4 hops / GUARDEDJOINT quadrants on the banking sandbox, in RESULTS.md; (48) identity v2 — `security/identity.py` ed25519 CredentialStore + Ed25519Verifier drop-in via create_app(identity=...), cryptography dep; (49) purple --baseline Policy-CI gate — save_baseline/load_baseline/compare_to_baseline + CLI flags, --ci exits 1 on regression; (50) FinBot CTF adapter — repo cloned + FinBotTarget w/ offline sim fallback; (51) community scaffolding — CONTRIBUTING/CODE_OF_CONDUCT/feature template + tag v1.0.0 exercising release.yml+cosign; (52) Mermaid architecture diagram ×3; (53) docs-site tutorials ×8; (54) GitHub Pages = user-side 2-click. Suite 1081→1259 (+178 TDD tests), ruff clean | ✅ Done | `target_series.py`, `identity.py`, `purple.py` baseline, `finbot.py`, `layer_targeting.py`, `crescendo.py`, `config_schema.py`, RESULTS.md ×3 sections, CONTRIBUTING.md, docs-site/tutorials/, tag v1.0.0; suite 1259 |
| Aug 24, 2026 | Tiers 1+2 benchmark runs PUBLISHED: Tier-1 deterministic re-verified (81 attacks, block 33.33%, ASR 66.67%, direct overrides 0%); Tier-2 multi-attempt series first publication (RESULTS.md) — CAISI methodology, budget 25, seed 42, 5-variant rotation; KEY FINDING: deterministic tier evasion 0%@attempt-1 → 100%@attempt-2 (static rules degrade fast under adaptive pressure — validates closed-loop purple + LLM layers); strict ASR 0% by construction (no LLM present); evasion metric added to multi_attempt.py via TDD (+3 tests). Tier-3 full-pipeline ready, awaiting API key | ✅ Done | RESULTS.md multi-attempt section, `multi_attempt.py`, tests/benchmarks/test_benchmark_tiers.py; suite 1081 |
| Aug 24, 2026 | Phase E2.7 submission package & enterprise quick wins SHIPPED (wave 6, parallel TDD subagents + orchestrator): (31) `DEVPOST.md` submission package; (32) `DEMO_SCRIPT.md` beat-by-beat 4-min script w/ shot list; (33) `BLOG_POST.md` #AllThingsAgenticHackathon draft; (34) Gemma provider option (`ARCHON_ATTACK_PROVIDER_KIND=gemma` → gemma-3-27b-it via Gemini compat); (35) cosign keyless signing in release.yml; (36) monthly killswitch_drill.yml w/ MTTC assertion; (37) shadow mode — create_app(shadow_mode=True) records 'request.shadow_would_block' audit events without enforcing (+ ShadowEvaluator module); (38) llm_tier.py env-gated full-pipeline benchmark; (39) multi_attempt.py CAISI attempt-budget curves over AgentDojo corpus; (40) security/caveats.py macaroon-style attenuating tokens (prefix-subsumption offline verification, allow/deny/max_spend/expires); (41) targets/adk_adapter.py Google ADK runner adapter; (42) docs.yml GitHub Pages workflow; (43) multi-tenancy v1 — migration v4 tenant_id + tenant-scoped ResultsStore. 44 FinBot CTF remains deferred. Suite 992→1065 (+73 TDD tests), ruff clean | ✅ Done | `DEVPOST.md`, `DEMO_SCRIPT.md`, `BLOG_POST.md`, `shadow.py`, `caveats.py`, `adk_adapter.py`, `multi_attempt.py`, `llm_tier.py`, workflows {release,killswitch_drill,docs}.yml, migrations v4; suite 1081 |
| Aug 23, 2026 | Phase E2.6 OWASP-aligned hardening SHIPPED (wave 5): (23) one-click purple runs — `archon purple --registry --agent-a --agent-b [--ci]` fusing BattleManager+compare_battles into delta verdicts; (24) scheduled fuzzing + autonomous red bots — nightly `fuzz.yml` workflow + `archon bot` continuous-probe loop; (25) kill-switch drill — `archon kill-switch --store --agent X [--restore]`, atomic revocation w/ MTTC measurement + audit event, enforced in armor (503 on revoked); (26) beyond-ASI patterns — recon/discovery, config-tamper persistence, staged-payload targets (`targets/gaps.py`, the three gaps OWASP's own appendix admits are uncovered); (27) plan-divergence detection — declared-intent vs executed-action trajectory analysis; (29) nonce store — HMAC replay-within-window limitation CLOSED (X-Nonce header, TTL+eviction, server default-on, SECURITY.md updated); (30) docs site — mkdocs.yml + docs-site/ 5 pages + security advisory template. IMP-6/28 FinBot CTF deferred post-hackathon. Suite 892→992 (+100 TDD tests), ruff clean | ✅ Done | `purple.py`, `bots.py`, `killswitch.py`, `targets/gaps.py`, `attacks/plan_divergence.py`, `authn.py` NonceStore, `mkdocs.yml`, `.github/workflows/fuzz.yml`; suite 992 |
| Aug 23, 2026 | OWASP deep review + Phase E2.6 planning: digested 4 OWASP resources (Red-Teaming Solutions Taxonomy v1.0, State of Agentic AI Security v2.01, GenAI LLM Top 10 2026, Agentic Top 10 2026) into a ~50-criterion C1–C6 capability scorecard; delta-verified all 9 competitor clones (all prior claims hold; momentum: deepeval 202 > promptfoo 135 > PyRIT 121 commits since Aug 1; agentdojo/ragas stalled at 0). Honest rating delivered: A− hackathon / B+ enterprise. Eight improvements scoped as ROADMAP Phase E2.6 items 23–30 (purple runs, fuzz+bots in CI, kill-switch drill, beyond-ASI patterns, plan-divergence detection, FinBot CTF validation, nonce store, docs site+advisory program) | ✅ Planned → shipped same day | `resources/` PDFs, ROADMAP E2.6, STATUS E2.6 checklist |
| Aug 23, 2026 | E2.10 HarmBench pack + corpus 150+ (probes.py: `harmbench_behavioral` 25 behavioral probes across six HarmBench harm domains w/ jailbreak frames; `jailbreak_personas` 25 DAN/developer-mode/no-restrictions persona frames; corpus 102→152, threshold test ≥150; classifier-regex discovery: 'ignore all previous instructions' does NOT match — normalized to 'ignore all instructions') — final roadmap code item | ✅ Done | `probes.py`, test_probes.py +8 tests; suite 884→892 |
|---|---|---|---|
| Aug 25 | Multi-tenancy v2 + SSO/SCIM wave | TenantStore enrollment isolation, X-Tenant-ID middleware, SCIM v2 router, OIDC RS256 verifier; provider retry backoff for shared-pool upstreams | 1,868→1,941 | ✅ Done |
| Aug 23, 2026 | E0.4 persistence hardening (registry/migrations.py: Migration/MIGRATIONS v1-v3/SchemaMigrator idempotent; results_store.py: durable battle store, upsert, share tokens sha256[:16] + resolve_share; CLI `archon results`); E2.5-15 certification conformance profile (reporting/certification.py: AIUC-1 6-category + CSA STAR Agentic L2 5-requirement CONTROL_MAP, ConformanceProfile.assess satisfied/partial/unmet, render_profile_md w/ readiness % + third-party-audit disclaimer, certification_readiness aggregate) — parallel subagent wave 4, 35 new TDD tests | ✅ Done | `registry/migrations.py`, `results_store.py`, `reporting/certification.py`, CLI results cmd; suite 849→884 |
| Aug 23, 2026 | E2.5-12 metrics productization (reporting/metrics.py: UAR, PED BFS, GUARDEDJOINT quadrants, dual-ASR w/ gap, measurement block declaring attempt_budget/adaptivity/judge per methodology commitments); E2.5-13 protocol-layer security (security/protocol.py: ToolFingerprint pinning, DriftMonitor rug-pull detection, A2A AgentCard §8.4 validation, registry provenance/injection scan); E2.5-14 compliance evidence automation (reporting/evidence.py: tamper-evident EvidenceArtifact, battle→control mapping EU-AI-ACT Art9/Art15 + NIST MEASURE-2/MANAGE-2 + ISO 42001 A.6.1.6, covenant/retention notes incl GSA 90-day + insurance ≥24mo, chain_of_custody hash chain) — parallel subagent wave 3, 74 new TDD tests | ✅ Done | `reporting/{metrics,evidence}.py`, `security/protocol.py`; suite 775→849 |
| Aug 23, 2026 | E0.1 CI pipeline (Actions matrix py3.11-3.13, ruff, coverage gate ≥85% — actual 93%) + release.yml tags/SBOM; E0.3 threat model (SECURITY.md, fuzz never-5xx suite, auth-boundary tests); E2.5 MCP battles; E2.6 supply-chain rug-pull; E2.8 trust exploitation; E2.9 rogue agents — parallel subagent wave, 86 new TDD tests | ✅ Done | `.github/workflows/`, `SECURITY.md`, `targets/{mcp_battles,supplychain,trust,rogue}.py`; suite 649→735 |
| Aug 23, 2026 | E0.2 packaging identity (MIT/Archon LICENSE, CHANGELOG 1.0.0, competition extra isolating a2a-sdk/google-adk/google-genai/openai); E2.7 ASI08 cascading failures (seeded amplification pipeline + ValidationDefense); E2.5-11 adaptive multi-attempt attacks (5-variant rotation, budget-declared results per CAISI methodology) — parallel subagent wave 2, 40 new TDD tests | ✅ Done | `LICENSE`, `CHANGELOG.md`, `targets/cascade.py`, `attacks/adaptive.py`, `tests/distribution/test_identity.py`; suite 735→775 |
| Aug 23, 2026 | ROADMAP COMPLETE + deep competitive review (SHIPPED): every item in ROADMAP v4 is now closed (P1 corpus, P2 severity, P3 sandbox battles, P4 trace-driven, P5a memory poisoning, P5b ASI07, N3 compare/checkpoint/UI/gallery/distribution). Deep review vs all OSS rivals (garak, promptfoo, PyRIT, NeMo, AgentDojo, DeepTeam, DeepEval, RAGAS, Snyk agent-scan — verified against cloned source) and closed-source context (Lakera, Zenity, HiddenLayer, Model Armor, Braintrust, Giskard, Splx) produced the §7.1/REPORT §3.1 agentic scorecards: Archon holds full coverage on all seven agentic dimensions; no competitor holds more than one partial | ✅ Done | `COMPETITIVE_ANALYSIS.md` §7.1, `REPORT_COMPARATIVE.md` §3.1, `STATUS.md`; suite 649 |
| Aug 23, 2026 | Post-hackathon N3 ecosystem completion (SHIPPED): (9) Web UI — `archon_armor/ui.py` + `archon ui`: zero-dependency dark-theme fleet dashboard at `/ui` (vanilla JS, no CDN, 10s auto-refresh), `/ui/api/summary` exposes agents+policies with api_secret never serialized, `/ui/api/battles` streams recent battles. (11) Contrib gallery — `contrib/` finance/healthcare/devops packs (18 namespaced probes) + README index + `ARCHON_CONTRIB_DIR` auto-discovery, every pack battle-tested. (12) Distribution — Homebrew formula (`packaging/homebrew/archon.rb`, uv-based, smoke-tested) + npm wrapper (`packaging/npm/archon-security`, npx → uv tool run / pipx fallback). ROADMAP Phase N3 fully closed | ✅ Done | `ui.py`, `contrib/`, `packaging/`, 29 TDD tests; suite 620→649 |
| Aug 23, 2026 | Post-hackathon N3 comparison engine + checkpoint/resume (SHIPPED): `archon_armor/compare.py` — A-vs-B diff of two battle reports (block-rate delta, per-category coverage deltas, newly blocked/unblocked probes, control status, severity movement) with `improved/regressed/equal` verdict, markdown/JSON rendering and `--ci` exit 1 on regression (`archon compare --a ref.json --b cand.json`). Plus crash-safe long scans: `checkpoints.py` + `execute(checkpoint_path=, resume_state=)` persist verdicts after every probe (atomic writes); `archon scan --checkpoint FILE` / `--resume FILE` skips completed probes and finalizes merged results. Verified end-to-end via CLI: truncated 3-of-4 checkpoint resumes to a completed 4-probe battle | ✅ Done | `compare.py`, `checkpoints.py`, 17 TDD tests; suite 603→620 |
| Aug 23, 2026 | Post-hackathon N2.6 ASI07 multi-agent trust-boundary attacks (SHIPPED): `targets/multiagent.py` — `MultiAgentSwarm` (agents, delegation edges, message transcript, `boundary_crossings()` detecting untrusted→trusted flow) + `TrustBoundaryTarget` modeling the ASI07 asymmetry: the coordinator sanitizes *direct* user input but trusts worker output blindly, so a directive buried under a benign research request slips the naive first-line filter, crosses the boundary via an unsanitized worker reply, and leaks the coordinator's secret. `sanitize_boundary=True` strips directives at the boundary (blue-team variant). Closed-loop: BranchingAttacker succeeds vs vulnerable swarm, fails vs sanitized; slow test proves request-side pipeline blocks 0 such payloads — only *boundary* defense works. promptfoo maps ASI07 and DeepTeam scores it as a metric; nobody else executes the attack | ✅ Done | `targets/multiagent.py`, 13 TDD tests; suite 590→603 |
| Aug 23, 2026 | Post-hackathon N2.5 live memory/vector-store poisoning (SHIPPED): `targets/memory.py` — `VectorMemoryStore` (persistent entries, token-overlap retrieval w/ stopword filtering, snapshot/diff), `plant_poison` (embeds `SYSTEM RULE:` directive inside innocuous kb-sourced doc), `RetrievalAgentTarget` (vulnerable RAG responder obeying directives found in retrieved content). The killer demo property: the *user query is benign* — poison fires on "What is the refund policy?" and the slow test proves the request-side pipeline blocks 0 such queries, i.e. only store-side defense works. Closed-loop: BranchingAttacker succeeds vs poisoned store, fails vs clean store, and remediation scrubbing kills a previously-successful attack. Nobody else manipulates real stores — promptfoo/DeepTeam simulate via text callbacks | ✅ Done | `targets/memory.py`, 14 TDD tests; suite 576→590 |
| Aug 23, 2026 | Post-hackathon N2.8 trace-driven attack generation (SHIPPED): `attacks/trace_driven.py` — mines JsonlTracer/OTLP-JSON span streams into a `TraceProfile` (defense layers observed vs layers that ever blocked, live tool names from `tool.*` spans/attrs, leaked error internals, agent identities/routes) and synthesizes targeted attacks: per-layer evasion payloads (base64 for normalization, delimiter confusion for spotlighting, forged role tags for segmentation, mode-confusion for execution_mode, redaction-evading exfil for output_guardrails, paraphrase for threat_classification), tool-name-targeted injection probes, and error-exploit extraction. `TraceAttack` duck-types the armor `Probe` contract (`name`/`probe_name`/`payload`/`category`) so generated attacks flow straight into `BattleManager.execute`; integration test mines a real traced pipeline run and battles the synthesized attacks. promptfoo/DeepEval only *evaluate* from traces — Archon *attacks* from them | ✅ Done | `attacks/trace_driven.py`, 13 TDD tests; suite 563→576 |
| Aug 23, 2026 | Post-hackathon N2.3 live tool-execution battles (SHIPPED): `targets/sandbox.py` — `SandboxEnvironment` (mutable state, deep-copy snapshots, key-level diffs), `Tool`, deterministic `directive_planner` (regex-parses transfer directives like a hijacked agent), `ToolSandboxTarget(TargetAdapter)` executing real tool calls and reporting ground-truth `raw["attack_success"]` from a caller-supplied goal check over env diffs; `BranchingAttacker._probe` now honors the env-state signal (backward-compatible: lexical scoring still used when `raw` lacks the key). Closed-loop test proves BranchingAttacker drains a vulnerable banking agent but cannot beat the Normalization+ThreatClassification shield. Direct counter to DeepTeam/promptfoo text-callback simulation | ✅ Done | `targets/sandbox.py`, `attacks/branching.py`, 10 TDD tests; suite 553→563 |
| Aug 23, 2026 | Post-hackathon N2.7 true severity derivation (SHIPPED AHEAD OF SCHEDULE): `reporting/severity.py` — CVSS-style 0–10 scores **derived from battle evidence** (threat-class base weight × execution-mode exposure [standard 1.0 → minimal 0.6] × evasion delivery multiplier for enc_/lat_ prefixes), stable vector strings `ARCHON:1/CAT:…/EXP:…/EV:…`, critical≥9/high≥7/medium≥4/low bands; aggregated into every `Battle.summary["severity"]` (unblocked non-control probes only) and rendered as a Severity section in HTML + Markdown evidence reports. Direct counter to DeepTeam's hardcoded `DEFAULT_IMPACT = MEDIUM` | ✅ Done | `severity.py`, `battles.py`, `compliance.py`, 15 TDD tests; suite 538→553 |
| Aug 23, 2026 | Post-hackathon N1.3 corpus 100+: Garak-lineage `encoding_evasion` pack (15 probes: base64, hex, rot13, url, url∘b64 combo, HTML entities, leetspeak, Cyrillic homoglyphs, zero-width chars — every payload test-enforced to decode to attack text via the normalizer and be blocked by the deterministic tier) + `latent_injection` pack (15 probes: instructions smuggled in resumes, invoices, email footers, web pages, READMEs, tickets, calendar invites, code comments, CSV cells, KB articles, error logs, contracts, transcripts, reviews, memos — all reference-blocked). Corpus 72→**102**; threshold test raised ≥70→≥100. Notable find: injection regex matches "ignore all/previous instructions" but NOT the three-word "ignore all previous instructions" — corpus now uses exact-match phrases; HTML-comment payloads are stripped by Layer 0 before classification (documented behavior) | ✅ Done | `probes.py`, 10 TDD tests; suite 528→538; `archon plugins --ci`: core 4 / encoding_evasion 15 / harmless_helpfulness 12 / latent_injection 15 / owasp_llm_10 56 |
| Aug 23, 2026 | P0 probe corpus expansion + false-positive canaries: corpus 53→72 (LLM02 ×4 new, LLM07 ×3 new, `harmless_helpfulness` pack of 12 benign canaries — security-article summary, lockpick fiction, wifi-password hygiene, recipes, etc.); test-enforced: ≥70 probes, all canaries unblocked by the reference pipeline (false-positive guard) | ✅ Done | `probes.py`, 9 TDD tests; suite 505→509; `archon plugins --ci`: core 4 / harmless_helpfulness 12 / owasp_llm_10 56 |
| Aug 23, 2026 | AgentDojo benchmark harness: loads all **27 published v1 injection tasks** (banking 9 / slack 5 / travel 7 / workspace 6) without installing agentdojo's LLM stack (sys.modules stubbing of `agent_pipeline`); 3 wrappers incl. AgentDojo's canonical `<INFORMATION>` template → 81 attacks through the reference pipeline; published ASR 66.7% / block 33.3% (deterministic tier; direct_override 0% ASR, structural wrappers pass to LLM layers) | ✅ Done | `packages/archon_benchmarks/`, `RESULTS.md`, 8 TDD tests; suite 509→517 |
| Aug 22, 2026 | §5.2 Registry MVP: `Registry` ABC, `AgentCard`/`SecurityPolicy`, InMemory + SQLite backends | ✅ Done | `packages/archon_core/registry/`, 14 TDD tests; suite 300→314 passing |
| Aug 22, 2026 | §5.2 Observability: LocalTracer (async-safe contextvar nesting), OTel-shaped JSON export, armor.request + per-layer spans with verdict attributes | ✅ Done | `observability/base.py`, 5 TDD tests; suite 322→327 passing |
| Aug 22, 2026 | §5.2 archon-armor proxy: FastAPI OpenAI-compatible endpoint, zero-trust X-Agent-ID, policy-driven pipeline, output guardrails, upstream abstraction (HTTPOpenAIUpstream) | ✅ Done | `packages/archon_armor/`, 8 TDD tests; suite 314→322 passing |
| Aug 22, 2026 | Sprint A1 remote scanning + Sprint A2 production OTel: `archon scan --target <url>` against any third-party guardrail; `OtelTracer` on the real OTel SDK with OTLP/HTTP export (`ARCHON_OTEL_EXPORTER=otlp` → Cloud Trace), contextvar parenting for async-safe span trees, scrubbing preserved | ✅ Done | `targets/openai_compat.py`, `observability/otel.py`, 19 TDD tests; suite 404→423 passing |
| Aug 22, 2026 | Sprint B live MCP + policy-as-code: `archon scan-mcp --url` connects to a running MCP server (Streamable HTTP) and pattern-scans its live tool metadata (fixing the latent `Finding.__dict__` serialization bug); `archon scan --config archon.yaml` YAML policy-as-code with flag-over-config precedence, pack/range validation, `examples/archon.yaml` | ✅ Done | `targets/mcp_live.py`, `config.py`, `examples/archon.yaml`, 22 TDD tests; suite 423→445 passing; live smoke test verified |
| Aug 22, 2026 | Sprint C branching attacker + behavioral MCP: `BranchingAttacker` (Hydra-style fan-out/pivot/prune; deterministic refusal-vs-leak scoring so verdicts never depend on an LLM judge; provider-failure degradation); `probe_tool` invokes live MCP tools with canonical injection payloads; `scan-mcp --probe-tool NAME` | ✅ Done | `attacks/branching.py`, `targets/mcp_live.py`, CLI flag, 18 TDD tests; suite 445→463 passing |
| Aug 22, 2026 | Sprint C3 multi-turn battles first-class: `BattleManager.execute(mode="multi_turn")` + `execute_sync`; attack tree → per-branch verdicts with `summary.attack_tree`; `archon battle --target --goal --seed --width --max-rounds --ci` (exit 1 when the attack succeeds); env-configured attack provider (Gemini OpenAI-compat default) | ✅ Done | `battles.py`, `archon_cli/main.py`, 6 TDD tests; suite 463→469 passing; live smoke verified |
| Aug 22, 2026 | P0 corpus breadth: owasp_llm_10 pack 8→49 probes covering all 10 OWASP LLM Top-10 categories (LLM01 x7 all reference-blocked, benign control added); breadth invariants test-enforced (>=50 total, >=3/category, uniqueness) | ✅ Done | `probes.py`, 5 TDD tests; suite 469→474; scorecard probe-corpus row 1→2 |
| Aug 22, 2026 | Plugin seams: `load_pack_file()` community packs (validated, duplicate-safe), `ARCHON_CONTRIB_DIR` auto-load, `archon plugins` seam inventory (packs/layers/targets/providers/MCP) | ✅ Done | `probes.py`, `archon_cli/main.py`, 7 TDD tests; suite 474→481 passing |
| Aug 22, 2026 | External-guardrail layer ("validate them"): `ExternalGuardrailLayer` delegates to any OpenAI-compatible guardrail endpoint (NeMo rails, Model Armor proxy, Promptfoo Guardrails) as a pluggable DefenseLayer; fail-closed on transport error; listed in `archon plugins` | ✅ Done | `defenses/external.py`, 6 TDD tests; suite 481→487 passing |
| Aug 22, 2026 | Fleet dashboard primitive: `FleetSummary` aggregates per-agent baselines into fleet metrics (registered/covered/avg-block-rate/degraded); `archon fleet --registry --baselines --min-block-rate --ci` (exit 1 below fleet minimum) | ✅ Done | `fleet.py`, `archon_cli/main.py`, 4 TDD tests; suite 487→491 passing |
| Aug 22, 2026 | Enterprise Postgres registry: `PostgresRegistry` (psycopg3, JSON-column layout matches SQLite, injectable connector seam, UniqueViolation→DuplicateAgentError, ThreadSafe), wired via `ARCHON_DATABASE_URL` | ✅ Done | `registry/postgres.py`, `server.py`, `[postgres]` extra; 10 tests (9 offline + env-gated integration); suite 491→500 |
| Aug 22, 2026 | Helm chart: `deploy/helm/archon-armor/` — non-root pod/container securityContext, liveness+readiness on /healthz, /data volume, Postgres env wiring (`ARCHON_DATABASE_URL`), ingress, service; structural tests + gated `helm lint`/`template` | ✅ Done | `deploy/helm/archon-armor/`, 5 structural tests + 2 gated; suite 500→505 |
| Aug 22, 2026 | §3 core contracts: `Exchange` model, `DefenseLayer` ABC, `DefensePipeline` (fail-closed, budget-aware, tracer hooks), 7 concrete layers wrapping proven defender modules via compat bridge | ✅ Done | `packages/archon_core/`, 14 new TDD tests; suite 286→300 passing |
| Aug 22, 2026 | P1.5 GCP path: DEPLOY_GCP.md (Cloud Run, Gemini OpenAI-compat upstream, Gemma bonus, observability proof, 4-min judge demo script) | ✅ Done | `DEPLOY_GCP.md`; live deployment requires GCP credentials (user-side) |
| Aug 22, 2026 | P1.4 Policy-CI: `BaselineStore` + `compare_summaries` (block-rate drop, control failure, per-probe unblock regressions), `Registry.update_policy` (ABC + SQLite persist), `archon scan --update-baseline/--gate-baseline` gates | ✅ Done | `archon_armor/baselines.py`, 10 TDD tests; suite 394→404 passing |
| Aug 22, 2026 | P1.3 compliance reports: battle summaries rendered as HTML/Markdown evidence artifacts, OWASP LLM Top-10 control mapping, pass/open verdicts, XSS-safe, `archon report` command | ✅ Done | `archon_core/reporting/compliance.py`, 7 TDD tests; suite 387→394 passing |
| Aug 22, 2026 | P1.2 MCP security: static tool-poisoning scanner (hidden instructions, cross-tool overrides, exfil endpoints, encoded exec), redacted evidence, `archon scan-mcp --ci` gate | ✅ Done | `archon_core/targets/mcp_scan.py`, 8 TDD tests; suite 379→387 passing |
| Aug 22, 2026 | P1.1 probe packs: named packs (core, owasp_llm_10) mapped to OWASP LLM Top-10 categories, per-category coverage matrix in battle summaries, pack selection via `/v1/battles {pack}` | ✅ Done | `archon_armor/probes.py`, 8 TDD tests; suite 371→379 passing |
| Aug 22, 2026 | P0 packaging: Dockerfile (non-root, /data volume, healthcheck-ready), docker-compose, `archon_armor.server` env-wired production factory (signed identity on by default), wheel build verified incl. console script | ✅ Done | `Dockerfile`, `docker-compose.yml`, `server.py`, 1 TDD test; suite 370→371 passing; `uv build --wheel` verified all packages |
| Aug 22, 2026 | P0 governance: `VersionedRegistry` (numbered policy history), `SqliteAuditTrail` (append-only, thread-safe), armor writes `request.blocked/allowed` audit events | ✅ Done | `registry/versioned.py`, `audit.py` (in core per dependency rule), 5 TDD tests; suite 365→370 passing |
| Aug 22, 2026 | P0 telemetry: `AttributeScrubber` (SSN/email/phone/bearer/API-key/card), `ScrubbingTracer`, `JsonlTracer` streaming OTLP-JSON-shaped spans to file | ✅ Done | `observability/scrubbing.py`, `observability/jsonl.py`, 6 TDD tests; suite 359→365 passing |
| Aug 22, 2026 | P0 CLI: `archon register/scan/serve` (argparse, zero deps), CI gate exit codes on block-rate threshold, JSON reports, console-script entry point | ✅ Done | `packages/archon_cli/`, 7 TDD tests; suite 352→359 passing; `uv run archon --help` verified live |
| Aug 22, 2026 | P0 authN: HMAC-signed requests (body-bound, replay-protected), `HmacVerifier`, per-agent secrets on AgentCard, `TokenBucketRateLimiter`; legacy header mode isolated as `AllowAllVerifier` | ✅ Done | `security/authn.py`, `security/ratelimit.py`, 18 TDD tests; suite 334→352 passing |
| Aug 22, 2026 | §3 provider seam + §5.2 battle/scan API: `LLMProvider` ABC, OpenAI-compat + Gemini providers (mock-transport tested), `BattleManager` with async submit/poll REST API and block-rate summaries | ✅ Done | `providers/`, `archon_armor/battles.py`, 7 TDD tests; suite 327→334 passing |

**Remaining for hackathon submission (§5.3):** Cloud Run deployment + GCP proof artifacts (user-side, needs GCP credentials), demo video, Devpost package. ADK target adapter / live Gemini demo path optional — Gemini already wired as the default attack provider via OpenAI-compat.

**Suite state:** 2,093 passed / 3 skipped (skips: live-Postgres integration behind `ARCHON_TEST_DATABASE_URL`; `helm lint`/`template` behind helm binary).







