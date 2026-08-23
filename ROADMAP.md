# Archon Roadmap (v5 — Enterprise-Ready Path)

> **Date:** August 23, 2026 · **Branch:** `hackathon-v2`
> **STATUS: v4 COMPLETE.** Every phase below (N1–N3) was shipped on Aug 23, 2026.
> This roadmap extends v4 with the enterprise-ready path to becoming the world's best
> agent security platform. Strategy rationale lives in [`BLUEPRINT_HACKATHON.md`](./BLUEPRINT_HACKATHON.md);
> competitor context in [`COMPETITIVE_ANALYSIS.md`](./COMPETITIVE_ANALYSIS.md).

---

## ✅ Shipped (v4 roadmap — all closed)

| Planned item | Shipped as | Where |
|---|---|---|
| Decouple from A2A / in-process execution | `TargetAdapter` ABC + `BattleManager` remote battles | `packages/archon_core/targets/`, `archon_armor/battles.py` |
| Multi-provider support | `LLMProvider` ABC; OpenAI-compat + Gemini providers | `packages/archon_core/providers/` |
| YAML configuration | `archon scan --config archon.yaml` | `packages/archon_core/config.py` |
| CLI with CI exit codes | `archon register / scan / scan-mcp / battle / serve / report / fleet / plugins` | `packages/archon_cli/` |
| Probe corpus + OWASP mapping | 120 probes across all 10 OWASP LLM Top-10 categories + encoding + latent + benign canaries + contrib | `packages/archon_armor/probes.py` |
| Community plugin packs | `load_pack_file()`, `ARCHON_CONTRIB_DIR` auto-load | `probes.py`, `archon_cli/main.py` |
| Runtime defense product | archon-armor FastAPI OpenAI-compat proxy | `packages/archon_armor/` |
| Enterprise governance | Versioned policies, immutable audit trail, Postgres registry | `registry/versioned.py`, `registry/postgres.py`, `audit.py` |
| Observability | Real OTel SDK → Cloud Trace, PII scrubbing, JSONL fallback | `observability/otel.py`, `scrubbing.py`, `jsonl.py` |
| Packaging & deploy | Wheel, non-root Dockerfile, docker-compose, Helm chart | `deploy/helm/archon-armor/` |
| MCP security | Static tool-poisoning scan + live behavioral probing | `targets/mcp_scan.py`, `mcp_live.py` |
| Third-party guardrail validation | `archon scan --target` + `ExternalGuardrailLayer` | `targets/openai_compat.py`, `defenses/external.py` |
| Policy-CI (defense regression gates) | `BaselineStore` + `--update-baseline/--gate-baseline` | `archon_armor/baselines.py`, `fleet.py` |
| Compliance evidence reports | OWASP-mapped HTML/MD battle reports | `reporting/compliance.py` |
| Adaptive multi-turn attacker | `BranchingAttacker` (Hydra-style, deterministic verdicts) | `attacks/branching.py` |
| Benchmark harness | AgentDojo v1: all 27 published injection tasks × 3 wrappers | `packages/archon_benchmarks/` |
| Live tool-execution battles | Sandbox targets with env-state ground truth | `targets/sandbox.py` |
| Live memory/vector-store poisoning | Real store manipulation + remediation loop | `targets/memory.py` |
| ASI07 trust-boundary attacks | Multi-agent swarm with boundary-crossing exploit | `targets/multiagent.py` |
| Evidence-derived severity scoring | CVSS-style 0–10 from battle evidence | `reporting/severity.py` |
| Trace-driven attack generation | Mines spans into targeted attacks | `attacks/trace_driven.py` |
| Comparison engine | A-vs-B battle diff with regression CI gate | `archon_armor/compare.py` |
| Checkpoint/resume | Crash-safe per-probe persistence | `archon_armor/checkpoints.py` |
| Web UI dashboard | Zero-dependency `/ui` fleet dashboard | `archon_armor/ui.py` |
| Contrib pack gallery | Finance/healthcare/devops probe packs | `contrib/` |
| Distribution | Homebrew formula + npm wrapper | `packaging/` |

---

## 🔜 Next (post-hackathon, priority order)

### Phase E1 — Enterprise Credibility (weeks 1–4)

These items close the gap between "impressive hackathon project" and "enterprise-ready platform":

1. **Full-pipeline benchmark run** — re-run the AgentDojo harness with LLM layers enabled; publish end-to-end ASR next to the deterministic-tier number in `RESULTS.md`. This is the single most credible artifact for enterprise buyers and researchers.
   - *Why:* The deterministic-tier ASR (66.7%) is honest but incomplete. Enterprises need to see the full pipeline's ASR to trust the defense.
   - *Effort:* 1–2 days (infrastructure: need LLM API access)

2. **Attacker diversity — local vLLM** under the existing `LLMProvider` seam; benchmark-driven tuning. (ClaudeNativeProvider ✅ already shipped — commit e37305c, 10 tests.)
   - *Why:* Garak and Promptfoo support multiple providers. Claude is covered natively; vLLM is free via its OpenAI-compat server + `OpenAICompatProvider` (zero new code).
   - *Effort:* 2–3 days

3. **Live demo + docs** — one Docker + Postgres + Helm template, one YouTube walkthrough. Makes it usable, credible, enterprise-pilot-ready.
   - *Why:* The hackathon demo is time-limited; a persistent demo is what enterprises actually evaluate.
   - *Effort:* 3–5 days

4. **Probe corpus 150+** — add adversarial benchmark suites (HarmBench) as packs; port top Garak/Promptfoo families via the loader; target 195+ to match Garak.
   - *Why:* Corpus breadth is Archon's weakest attack-side row. Community pack loader makes this crowd-solvable.
   - *Effort:* 1–2 weeks (incremental)

### Phase E2 — The Unclaimed Gaps (weeks 5–12)

*Each of these was verified absent-or-weak across all 9 competitor repos (see `COMPETITIVE_ANALYSIS.md` §5):*

5. **Live MCP tool-execution battles** — spawn/connect an MCP server, enumerate tools, run poisoning + confused-deputy battles against real tool calls. Extend `MCPTarget` beyond static scanning.
   - *Why:* OWASP ASI02 (Tool Misuse & Exploitation) is the hottest agentic threat; Snyk is static-only; nobody does behavioral MCP battles.
   - *Effort:* 2–3 weeks

6. **ASI04 Agentic Supply Chain attacks** — schema manipulation, description deception, permission misrepresentation, registry poisoning.
   - *Why:* OWASP ASI04 is untested by anyone; supply chain attacks against MCP tools and agent registries are emerging threats.
   - *Effort:* 1–2 weeks

7. **ASI08 Cascading Agent Failures** — test multi-agent systems for cascade-recovery behavior.
   - *Why:* OWASP ASI08 is untested; complex agent interactions produce unexpected cascading failures.
   - *Effort:* 1–2 weeks

8. **ASI09 Human-Agent Trust Exploitation** — social engineering attacks that exploit human trust in agent outputs.
   - *Why:* OWASP ASI09 is untested; agents that humans trust can be weaponized.
   - *Effort:* 1–2 weeks

9. **ASI10 Rogue Agents** — detect and test for agents that deviate from their intended behavior.
   - *Why:* OWASP ASI10 is untested; rogue agents are the ultimate failure mode.
   - *Effort:* 1–2 weeks

10. **HarmBench benchmark integration** — run the full HarmBench evaluation suite for researcher credibility.
    - *Why:* HarmBench is the gold standard for red teaming evaluation; publishing numbers there establishes credibility.
    - *Effort:* 1–2 weeks

### Phase E3 — Ecosystem & Distribution (months 3–6)

11. **Plugin marketplace directory** — curated `contrib/` gallery indexed in README; CI matrix for community pulls; `archon plugins publish` command.
    - *Why:* Garak and Promptfoo have thriving plugin ecosystems; Archon's five seams need equivalent community engagement.
    - *Effort:* 1–2 weeks

12. **Docs site** — dedicated documentation site (MkDocs or Docusaurus) with tutorials, API reference, and contribution guides.
    - *Why:* Enterprise adoption requires excellent documentation; Garak and Promptfoo have this.
    - *Effort:* 1–2 weeks

13. **Managed cloud control plane** — multi-tenant armor deployments, scheduled continuous battles, alerting on baseline regressions.
    - *Why:* This is the revenue layer over the MIT open core; enterprises want managed security, not self-hosted.
    - *Effort:* 2–3 months

14. **Commercial partnerships** — integrate with NeMo Guardrails, Model Armor, Lakera as validated defense targets; co-marketing opportunities.
    - *Why:* "We validate NeMo" is marketing they can't refuse; partnerships accelerate adoption.
    - *Effort:* ongoing

### Phase E4 — Market Leadership (months 6–12)

15. **Published research** — submit Archon as a research contribution to a top security conference (USENIX Security, IEEE S&P, CCS).
    - *Why:* Academic credibility is the ultimate enterprise signal; Garak and AgentDojo have this.
    - *Effort:* 2–3 months (research paper)

16. **Enterprise features** — RBAC, SSO integration, multi-tenant isolation, SLA guarantees.
    - *Why:* Enterprise procurement requires these features; currently only commercial tools offer them.
    - *Effort:* 2–3 months

17. **AI agent security certification** — partner with OWASP or NIST to create an agent security certification program using Archon as the testing backend.
    - *Why:* Certification programs create recurring revenue and market lock-in; OWASP Agentic Top-10 provides the vocabulary.
    - *Effort:* 3–6 months (partnership)

---

## Explicitly descoped (and why)

- **RL-adaptive attack strategies** — deterministic branching + provider-driven mutation covers the practical threat model at a fraction of the cost.
- **Own eval-quality metrics** — DeepEval/RAGAS own that space; Archon's helpfulness regression ("normal user test") covers the security-relevant slice.
- **Becoming a guardrail library** — NeMo/DeepTeam ship DIY guard libraries; Archon ships the *measurable enforcement point* plus the adversary that validates it.
- **Becoming a governance platform** — Obot and Zenity own that space; Archon focuses on security testing.

---

## Enterprise Readiness Gap Analysis

| Gap | Severity | Evidence | Closure path |
|---|---|---|---|
| Probe corpus breadth vs Garak (195) | 🟠 Medium | 120 probes vs 195 | Community pack loader + HarmBench integration |
| Provider diversity (local vLLM) | 🟡 Low | Claude ✅ shipped (`ClaudeNativeProvider`, commit e37305c); OpenAI-compat + Gemini + Anthropic covered | vLLM OpenAI-compat endpoint (zero code — reuse `OpenAICompatProvider`) |
| Live demo + persistent docs | 🟠 Medium | Hackathon demo time-limited | Docker + Postgres + Helm + YouTube walkthrough |
| Full-pipeline benchmark (LLM layers) | 🟠 Medium | Deterministic-tier only published | Re-run with LLM layers enabled |
| ASI04/ASI08/ASI09/ASI10 coverage | 🟠 Medium | 6/10 OWASP Agentic risks covered | Phase E2 targets |
| Community/team size | 🟡 Low (product) | Solo developer | Plugin seams + MIT license attract contributors |
| Managed cloud offering | 🟡 Low (post-adoption) | Self-hosted only | Phase E3 control plane |

---

## The Enterprise Buyer's Perspective

An enterprise CISO evaluating agent security tools needs:

1. **Pre-deployment testing** — "Can I test my agent before it goes live?" → Archon's `archon battle` + `archon scan`
2. **Runtime protection** — "Can I protect my agent in production?" → Archon's `archon-armor` proxy
3. **Evidence of effectiveness** — "Can I prove the protection works?" → Archon's per-layer telemetry + OTel traces + compliance reports
4. **CI/CD integration** — "Can I put this in my pipeline?" → Archon's `--ci` exit codes + YAML config + Helm chart
5. **Vendor neutrality** — "Am I locked in?" → Archon's MIT license + five extension seams + self-hostable
6. **Standards alignment** — "Does this map to OWASP/NIST?" → Archon's OWASP LLM Top-10 + Agentic Top-10 coverage

**No other tool satisfies all six.** Garak/Promptfoo satisfy 1+4. NeMo/Model Armor satisfy 2. PyRIT satisfies 1+3 (partially). Archon satisfies all six — that's the enterprise pitch.

---

## Success Metrics (12-month targets)

| Metric | Target | Current |
|---|---|---|
| GitHub stars | 5,000+ | ~500 |
| Probe corpus | 200+ | 120 |
| Published benchmarks | 3+ (AgentDojo, HarmBench, custom) | 1 (AgentDojo deterministic) |
| Enterprise pilots | 5+ | 0 |
| Community plugins | 50+ | 18 (contrib/) |
| Documentation pages | 100+ | ~20 |
| CI/CD integrations | GitHub Actions, GitLab CI, Jenkins | GitHub Actions (via --ci) |

---

*Maintained alongside code on `hackathon-v2`. Bump version/date on substantive edits.*
