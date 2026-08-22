# Archon — Competitive & Market Analysis (v3)

> **Date:** August 22, 2026 · **Method:** every tool claim below was verified against the project's live GitHub repo/docs on this date. Star counts are approximate (±0.2k). Historical versions of this file contained errors — see the Corrections Log at the end.

---

## 1. Executive Summary

The LLM/agent security market has consolidated into four distinct layers, and **no single open-source tool spans them**:

1. **Static scanning** of models/configs (Garak; Snyk Agent Scan for MCP/skills)
2. **Eval-style red teaming** inside dev workflows (Promptfoo — now part of OpenAI)
3. **Campaign attack orchestration** (PyRIT — multi-turn, endpoint-agnostic library)
4. **Runtime guardrails** (Google Model Armor, NeMo Guardrails, LLM Guard)

Agent-specific testing exists only as a benchmark (**AgentDojo**, ETH Zurich) and a static scanner (Snyk Agent Scan) — nobody offers *continuous, behavioral, red-vs-blue agent testing with a shippable defense*. That is Archon's wedge: proven multi-turn attack engine + packaged measurable defense proxy + extensible core.

## 2. Verified Competitor Matrix

| Tool | Owner | Stars | License | Red team | Defense eval | Multi-turn | Agentic/tool surface | Runtime product |
|---|---|---|---|---|---|---|---|---|
| **Promptfoo** | Part of OpenAI (still MIT OSS) | ~24.5k | MIT | ✅ plugins+strategies | ❌ | ⚠️ limited | ⚠️ agents/RAGs as targets | ❌ |
| **Garak** | NVIDIA | ~8.9k | Apache-2.0 | ✅ probes/detectors | ❌ | ❌ (mostly single-turn) | ❌ | ❌ |
| **PyRIT** | Microsoft | ~4.3k | MIT | ✅ orchestrators/converters/scorers | ❌ | ✅ | ⚠️ thin | ❌ |
| **NeMo Guardrails** | NVIDIA | ~7.0k | Apache-2.0 | ❌ | n/a (it IS a guardrail) | — | ⚠️ rails | ✅ runtime toolkit |
| **Snyk Agent Scan** (ex mcp-scan) | Snyk | ~2.9k | Apache-2.0 | ⚠️ static only | ❌ | ❌ | ✅ MCP/skills scanning | ❌ |
| **AgentDojo** | ETH Zurich Spy Lab | ~762 | MIT | ✅ injection suite | ✅ defenses evaluated | ✅ in-benchmark | ✅ tool-using agents | ❌ benchmark only |
| **LLM Guard** | Protect AI (→ Palo Alto Networks) | ~3k | MIT | ❌ | n/a (runtime scanner) | — | ❌ | ✅ input/output scanners |
| **Archon** | Independent | — | MIT | ✅ adaptive multi-turn (GOAT-style, deterministic signal extraction) | ✅ 5-layer pipeline, budget-aware | ✅ stateful 7-round battles | ⚠️ A2A agents today; MCP planned | 🚧 armor proxy in progress |

### 2.1 Platform/commercial context

- **Google Cloud Model Armor** (GA): bidirectional prompt/response screening; integrates Vertex AI, Apigee, Agent Gateway, LangChain, MCP servers. Category validation *and* hackathon-track namesake. It filters but does not let you measure your own pipeline against adaptive attacks — Archon's measurability angle complements rather than competes head-on.
- **Commercial:** Lakera (Guard/Red), Zenity, HiddenLayer, Mindgard, Haize Labs — enterprise budget validation; none open-source their red/blue loop.
- **Standards:** OWASP Agentic Security Initiative — Top 10 for Agentic Applications (2026), secure-MCP guidance. Archon's threat taxonomy should track these.

## 3. The Gap Archon Owns

| Capability | Archon | Best alternative |
|---|---|---|
| Multi-turn stateful attacks w/ deterministic signals | ✅ | PyRIT (library UX), AgentDojo (fixed benchmark) |
| Attack **and** defense in one framework | ✅ | AgentDojo evaluates both, but static/benchmark-only |
| Defense shipped as drop-in runtime proxy with per-layer telemetry | 🚧 (unique when shipped) | Model Armor filters, gives filter verdicts — not adversarially validated by you |
| Helpfulness regression ("normal user test") alongside security | ✅ | ❌ nobody |
| Extensible via stable ABCs across attack/defense/provider/target/reporter seams | 🚧 design done (BLUEPRINT §3.2) | Garak's plugin system is probe-side only |

**Honest weaknesses to fix (priority order):** not pip-installable as a tool; single-provider config; no CI mode; small probe corpus vs Garak/Promptfoo; no MCP target adapter; no OTel; repo naming (`arcon`). Full table with closure paths: `BLUEPRINT_HACKATHON.md` §4.

## 4. Threat & Standards Alignment (OWASP Agentic Top-10 mapping)

| OWASP Agentic risk (2026 Top-10) | Archon coverage today | Planned |
|---|---|---|
| Prompt injection (direct/indirect) | ✅ core attack surfaces + L0–L4 defenses | — |
| Tool misuse / tool poisoning | ❌ | `MCPTarget` adapter + poisoning strategies (v0.3) |
| Memory/context poisoning | ⚠️ partial (multi-round state attacks) | memory-surface strategies |
| Privilege compromise / confused deputy | ⚠️ via scenario plugins | policy-aware targets |
| Resource exhaustion | ❌ | load-style strategies |
| Data exfiltration / PII leak | ✅ leak detection + output guardrails | — |

Aligning terminology to this table in the Devpost description signals fluency to judges.

## 5. Market Timing

- Agentic adoption is exploding (agent frameworks, MCP ecosystem growth) while security tooling remains either scanner-era or benchmark-era.
- OpenAI acquiring Promptfoo validates M&A appetite for this category; Snyk acquiring Invariant Labs shows the agent-security consolidation has already started.
- The winning open-source position is the one developers can self-host and extend **before** platform vendors close it off.

## 6. Corrections Log (vs. prior version of this file)

1. ❌ "Archon \| Xiaomi" → Archon is independent (Yasir Raza).
2. ⚠️ Stale star counts updated: Promptfoo 22.4k→~24.5k, Garak 8.2k→~8.9k, PyRIT 4k→~4.3k.
3. ✅ "Promptfoo = OpenAI" retained — now *verified* against Promptfoo's README rather than assumed.
4. ➕ Added previously missing competitors: AgentDojo, NeMo Guardrails, Snyk Agent Scan/mcp-scan, Google Model Armor; commercial context (Lakera, Zenity, etc.).
5. 🧹 Removed unverifiable claims ("157 plugins" kept only with approximation framing; PyRIT coverage percentages dropped).

---

*Superseded historical analyses live in `ALTERNATIVES_COMPARISON.md`, `RESEARCH_REPORT.md`, `PROJECT_REVIEW.md` (correction banners applied).*

---

## 7. Enterprise Readiness Scorecard (post Phase 5 — Aug 2026)

Scale: **0 = absent · 1 = partial · 2 = best-in-class**. Archon column reflects code on `hackathon-v2` (334 tests).

| # | Enterprise dimension | **Archon v3** | Promptfoo | Garak | PyRIT | NeMo Guard | Model Armor | Snyk Agent Scan |
|---|---|---|---|---|---|---|---|---|
| 1 | Multi-turn adaptive attack engine | **2** ✅ | 1 | 1 | **2** | 0 | 0 | 0 |
| 2 | Defense evaluation (red vs blue loop) | **2** ✅ | 0 | 0 | 0 | 0 | 0 | 0 |
| 3 | Runtime defense as deployable product | **2** 🆕 armor proxy | 0 | 0 | 0 | **2** | **2** | 0 |
| 4 | Per-layer defense telemetry (measurable defense) | **2** 🆕 unique | 0 | 0 | 0 | 0 | 1 (filter verdicts only) | 0 |
| 5 | Agent identity/registry/policy governance | 1 ⚠️ basic | 0 | 0 | 0 | 0 | **2** (GCP IAM) | 0 |
| 6 | Observability & audit evidence | 1 ⚠️ local tracer only | 1 | 1 | 0 | 1 | **2** | 1 |
| 7 | CI/CD developer experience (CLI, exit codes) | **0 ❌** | **2** | 1 | 0 | 1 | n/a | **2** |
| 8 | Threat/probe corpus breadth | **0 ❌** (4 probes) | **2** | **2** | 1 | 0 | internal | 1 (static MCP) |
| 9 | MCP/tool-surface testing | **0 ❌** | 1 | 0 | 0 | 0 | 1 (integration) | **2** (static) |
| 10 | Production hardening (authN/Z, HA, multi-tenant) | **0 ❌** header-only | 1 | 0 | 0 | 1 | **2** | 1 |
| 11 | Open source + self-hostable | **2** | **2** | **2** | **2** | **2** | 0 | 2 (no contribs) |
| 12 | Cost efficiency (LLM-budget accounting built-in) | **2** ✅ | 0 | 0 | 0 | 0 | token-priced | n/a |

**Reading the table:** nobody scores ≥2 on rows 1+3+4 simultaneously except Archon. That triple — *adaptive attacks, a shippable defense, and proof that the defense works* — is the company-making position. But rows 7, 8, 10 are hard zeros, and enterprises will not pilot a tool with a zero in CI/CD or production hardening regardless of how good the engine is.

## 8. The Enterprise Gap List (prioritized by deal-blocking severity)

### P0 — Blockers (an enterprise cannot pilot without these)
| Gap | Why it blocks deals | Closure (est.) |
|---|---|---|
| **AuthN/AuthZ on armor** — `X-Agent-ID` is spoofable today; need signed identity (HMAC/JWT or mTLS), per-agent API keys, rate limiting | Zero-trust claim collapses if identity is a plain header | ~1 wk |
| **`archon` CLI with CI mode** — `archon scan --target … --ci` emitting JSON + exit codes so security gates run in GitHub Actions/GitLab | Enterprises adopt via pipelines, not Python APIs; this is how Promptfoo spread | ~1 wk |
| **Real OTel exporter + PII-scrubbing log pipeline** | Security teams live in Datadog/Splunk; audit logs must not themselves leak PII | ~3 days |
| **Postgres registry backend + policy versioning + immutable audit trail** | SQLite ≠ prod; auditors require "who changed which policy when" | ~1 wk |
| **Packaging**: pip-installable `archon`, Docker image, Helm chart | Procurement/deployment reality | ~3 days |

### P1 — Differentiators (what wins evaluations)
| Gap | Opportunity | Closure (est.) |
|---|---|---|
| **Probe corpus expansion mapped to OWASP LLM Top-10 + Agentic Top-10** with a coverage matrix in every report | Turns "small corpus" weakness into "complete standards coverage" story; crowd-extensible via `AttackStrategy` seam | ongoing, first pack ~1 wk |
| **MCP target adapter + tool-poisoning battle suite** | Hottest agentic threat; Snyk is static-only — behavioral MCP testing is open | ~1–2 wks |
| **Compliance evidence reports** (HTML/PDF): battle results auto-mapped to NIST AI RMF / EU AI Act / OWASP controls | The artifact CISOs actually buy; no competitor produces adversarially-validated compliance evidence | ~1 wk |
| **Third-party DefenseLayer SDK** (entry-point plugin registration) | NeMo/Lakera guards become testable targets AND pluggable defenses → ecosystem lock-in | ~1 wk |
| **Policy-CI: regression battles gated on policy/config changes** ("defense regression testing") | Unique category Archon invents: like load-testing for security policy | ~1 wk |

### P2 — Moat (post-adoption)
- Continuous scheduled battles + fleet dashboard (multi-agent estates)
- Attacker learning loop (Promptfoo Meta-Agent-style evolutionary strategies) feeding on real armor telemetry
- Managed cloud control plane (the revenue layer over the open core)

## 9. Path to "World's Best" — the strategy in three sentences

1. **Own "measurable defense":** be the only platform where a CISO can point an adaptive attacker at their deployed guardrail config and hand auditors the trace as evidence — nobody else closes that loop.
2. **Meet enterprises where they are:** CLI-first CI integration, OTel-native telemetry, Postgres/Helm deployment, compliance-mapped reports — boring reliability features beat exotic attack research for deal flow.
3. **Out-open the incumbents:** Garak/Promptfoo proved communities form around plugin seams; Archon has five seams (attack/defense/provider/target/reporter) — make each one documented, versioned, and contribution-friendly before competitors copy the red/blue-loop category.



