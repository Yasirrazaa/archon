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


