# ARCHON v3 BLUEPRINT — World-Class Agent Security Platform & Hackathon Victory Plan

> **Version:** 3.0 · **Date:** August 22, 2026 · **Branch:** `hackathon-v2` (`main` untouched)
> **Supersedes:** all previous blueprint versions. Every competitor claim below was verified against live sources on Aug 22, 2026 (see §9 Corrections Log).

---

## 0. Document Map — How the Docs Fit Together

| Document | Role | Status |
|---|---|---|
| `README.md` | Product front door — what Archon is, how to run it | ✅ Updated v3 |
| `COMPETITIVE_ANALYSIS.md` | Verified competitor & market intelligence | ✅ Rewritten v3 |
| `BLUEPRINT_HACKATHON.md` | This file — product architecture + competition strategy | ✅ Rewritten v3 |
| `ROADMAP.md` | Post-hackathon product roadmap (core-first) | ✅ Updated v3 |
| `PROJECT_REVIEW.md`, `ALTERNATIVES_COMPARISON.md`, `RESEARCH_REPORT.md` | Historical research archives | ⚠️ Corrections applied; superseded by the two docs above |

**Reading order for judges/collaborators:** README → COMPETITIVE_ANALYSIS → this file → ROADMAP.

---

## 1. Strategy in One Paragraph

Archon's core is already differentiated and proven (286 passing tests, ranked 6th Defense in the Berkeley AgentBeats arena): an adaptive multi-turn attack engine (GOAT-style) and a budgeted multi-layer defense pipeline that no open-source competitor combines. The path to world-class is **not** more attack research — it is **productization**: extract the attack engine and defense pipeline into a provider-agnostic core library, ship the defense pipeline as a deployable runtime proxy (the one thing Garak/Promptfoo/PyRIT categorically don't do), wrap everything in extensible ABCs so new providers/targets/plugins bolt on without touching core, and treat hackathon integrations (Google ADK, Gemini, GCP, Cloud Run) as **optional adapters**, not architectural dependencies. Win the hackathon *because* the product is good, not by warping the product around the hackathon.

## 2. Verified Market Intelligence (as of Aug 22, 2026)

### 2.1 Open-source leaders (all facts live-checked)

| Tool | Owner | Stars | License | What it actually does | Real weaknesses (honest) |
|---|---|---|---|---|---|
| **Promptfoo** | **Part of OpenAI** (per its own README; remains MIT open source) | ~24.5k | MIT | CLI/library for LLM evals + red teaming of prompts, agents, RAGs; declarative config; web viewer; CI/CD + code-scan action; pip/brew/npx | Attack-side only; assertion-centric; limited multi-*turn* statefulness; no runtime protection story |
| **Garak** | NVIDIA (Derczynski, Galinkin et al.) | ~8.9k | Apache-2.0 | "nmap for LLMs": probe/detector/generator/harness plugin system; static, dynamic, adaptive probes; wide generator coverage | Primarily single-turn model probing; no defense evaluation; no agent-runtime visibility |
| **PyRIT** | Microsoft (moved `Azure/PyRIT` → `microsoft/PyRIT`) | ~4.3k | MIT | Orchestrators, converters, targets, scorers; genuine multi-turn attack automation; works against **any** HTTP/OpenAI-compatible endpoint — Azure optional, not required | Library not tooling (steep ramp); no blue-team side; no runtime defense product |
| **AgentDojo** | ETH Zurich Spy Lab (w/ Invariant Labs founders) | ~762 | MIT | Dynamic benchmark environments (workspace/travel/banking/slack) evaluating prompt-injection **attacks AND defenses** on LLM agents | Benchmark not product; fixed task suites; no continuous-testing or runtime component |
| **Snyk Agent Scan** (ex Invariant Labs *mcp-scan*) | Snyk | ~2.9k | Apache-2.0 | Static scanner for MCP servers, agent skills, tool-poisoning detection; CI mode | Static/config scanning only; no behavioral multi-turn testing; closed to contributions |
| **NeMo Guardrails** | NVIDIA | ~7.0k | Apache-2.0 | Programmable runtime guardrails (Colang rails) for conversational apps | Runtime toolkit, not a tester; no adversary; no eval harness |

### 2.2 Platforms & commercial context

- **Google Cloud Model Armor** — real GA service in Security Command Center: bidirectional prompt/response screening (jailbreak, prompt-injection, malicious URLs, PII, grounding), integrates with Vertex AI, Apigee, Agent Gateway, LangChain, MCP servers. It is simultaneously the category Archon's defense pipeline plays in **and** a named component of the hackathon's Fortified Enterprise Fleet track.
- **OWASP Agentic Security Initiative** — *Top 10 for Agentic Applications (2026)*, *State of Agentic AI Security & Governance*, secure-MCP guidance. Aligning Archon's threat taxonomy to OWASP's gives instant credibility and vocabulary judges recognize.
- Commercial vendors (Lakera Guard/Red, Zenity, HiddenLayer, Mindgard, Haize Labs, Protect AI→Palo Alto Networks) validate enterprise budgets but none ship an open, self-hostable red/blue testing loop.

### 2.3 The structural gap nobody fills

Buyers must currently stitch ≥3 tools: a scanner (Garak/Promptfoo) for pre-deployment probes, an orchestration library (PyRIT) for campaigns, and a separate runtime guardrail (Model Armor / LLM Guard / NeMo) whose effectiveness they can never *measure*. **The unclaimed position: one platform where attack, defense, and observability meet — point Archon's attacker at Archon's (or anyone's) defense and get evidence, not vibes.**

Three artifacts required — none of the competitors have all three:
1. Multi-turn stateful attack engine with deterministic signal extraction ✅ *(exists today)*
2. Defense pipeline packaged as a drop-in runtime proxy with per-layer telemetry 🚧 *(logic exists, packaging doesn't)*
3. Extensible core where third parties add strategies/layers/providers via stable ABCs 🚧 *(partially exists via scenario plugins)*

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

1. **v0.2:** pip-installable `archon` CLI, YAML config, CI exit codes → compete for Promptfoo's security niche.
2. **v0.3:** MCP target adapter + tool-poisoning attack suite → own the OWASP Agentic Top-10 conversation before Snyk Agent Scan's static-only approach can follow.
3. **v0.4:** AgentDojo benchmark integration + published results → researcher credibility.
4. **v1.0:** registry server, multi-tenant armor deployments, OTel-native everywhere.

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

---

*End of BLUEPRINT v3. Maintain this document alongside code changes on `hackathon-v2`; bump version and date on every substantive edit.*

---

## 10. Implementation Progress Log

| Date | Phase | Status | Evidence |
|---|---|---|---|
| Aug 22, 2026 | §5.2 Registry MVP: `Registry` ABC, `AgentCard`/`SecurityPolicy`, InMemory + SQLite backends | ✅ Done | `packages/archon_core/registry/`, 14 TDD tests; suite 300→314 passing |
| Aug 22, 2026 | §5.2 Observability: LocalTracer (async-safe contextvar nesting), OTel-shaped JSON export, armor.request + per-layer spans with verdict attributes | ✅ Done | `observability/base.py`, 5 TDD tests; suite 322→327 passing |
| Aug 22, 2026 | §5.2 archon-armor proxy: FastAPI OpenAI-compatible endpoint, zero-trust X-Agent-ID, policy-driven pipeline, output guardrails, upstream abstraction (HTTPOpenAIUpstream) | ✅ Done | `packages/archon_armor/`, 8 TDD tests; suite 314→322 passing |
| Aug 22, 2026 | §3 core contracts: `Exchange` model, `DefenseLayer` ABC, `DefensePipeline` (fail-closed, budget-aware, tracer hooks), 7 concrete layers wrapping proven defender modules via compat bridge | ✅ Done | `packages/archon_core/`, 14 new TDD tests; suite 286→300 passing |






