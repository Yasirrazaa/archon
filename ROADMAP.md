# Archon Roadmap (v5 — Enterprise-Ready Path)

> **Date:** August 23, 2026 · **Branch:** `hackathon-v2` · **v5.1**
> **STATUS: v4 COMPLETE.** Every phase below (N1–N3) was shipped on Aug 23, 2026.
> This roadmap extends v4 with the enterprise-ready path to becoming the world's best
> agent security platform. Strategy rationale lives in [`BLUEPRINT_HACKATHON.md`](./BLUEPRINT_HACKATHON.md);
> competitor context in [`COMPETITIVE_ANALYSIS.md`](./COMPETITIVE_ANALYSIS.md).
>
> **v5.1 additions:** Phase E0 (engineering maturity) and Phase E2.5 (research-derived
> differentiators) are grounded in the Aug-23 landscape research
> ([`docs/LANDSCAPE_2026.md`](./docs/LANDSCAPE_2026.md)) and an internal code-quality audit
> (see gap analysis at the bottom). The core thesis: *the differentiated capabilities are
> built and tested — what stands between Archon and enterprise adoption is the "boring 80%":
> CI, packaging hygiene, docs, persistence, and community.*

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

### Phase E0 — Engineering Maturity (weeks 0–3) ← *do this first*

*Code-quality audit verdict: **B+ hackathon, C+ enterprise** (6,204 src / 7,466 test LOC,
892 passing). The hard part is done; this phase is mechanical, high-leverage work.*

1. **CI pipeline ✅ SHIPPED (Aug 23 — .github/workflows/ci.yml test matrix py3.11-3.13 + ruff + --cov-fail-under=85 gate at 93% actual + release.yml tags/SBOM)** — GitHub Actions: test matrix (py3.11/3.12/3.13), ruff + mypy strict on
   `packages/`, coverage gate ≥85%, release workflow with tags + SBOM.
   - *Why:* All 892 tests pass locally — nothing enforces that on PRs. This is the single
     biggest credibility gap; promptfoo runs thousands of CI checks per commit.
   - *Effort:* 3–5 days
2. **Split packaging** ✅ SHIPPED (Aug 23 — LICENSE MIT/Archon Contributors, CHANGELOG.md [1.0.0], pyproject version 1.0.0, competition extra isolating a2a-sdk/google-adk/google-genai/openai out of core deps; test_identity.py) — `archon-core` installable without the competition stack
   (`a2a-sdk`, `google-adk`, `google-genai`, `openai` currently pollute the root install);
   rename LICENSE holder ("Copyright 2025 AgentBeats" → Archon); v1.0.0 tag + CHANGELOG.
   - *Why:* Identity confusion + legacy baggage block enterprise procurement review.
   - *Effort:* 2–3 days
3. **Threat-model archon-armor itself** ✅ SHIPPED (Aug 23 — SECURITY.md + 200-iteration seeded fuzz suite never-5xx invariant + auth-boundary tests incl. replay-window honesty) — fuzz the request parser, document the HMAC auth
   boundary, rate-limit persistence story, TLS deployment guidance, SECURITY.md + CVE process.
   - *Why:* A security tool with no threat model of itself is a contradiction buyers notice.
   - *Effort:* 1 week
 4. **Persistence hardening** — ✅ SHIPPED (Aug 23, wave 4): `archon_core.registry.migrations`
    (Migration/MIGRATIONS v1-v3/SchemaMigrator idempotent apply_all), `archon_armor.results_store.ResultsStore`
    (durable battle results, upsert, newest-first listing, deterministic sha256 share tokens + resolve_share),
    CLI `archon results --db [--agent-id] [--limit] [--share]`; 17 TDD tests. Postgres battle-testing remains
    an operational task (CI postgres job now runs the integration suite on every push).
    - *Why:* SQLite-first is demo-grade; enterprises need migrations and durable results.
    - *Effort:* 1–2 weeks

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

5. **Live MCP tool-execution battles** ✅ SHIPPED (Aug 23 — targets/mcp_battles.py: description-hijack routing proof, leak-token ground truth, rug-pull mutation hook, mcp-scan-style scan_defenses) — spawn/connect an MCP server, enumerate tools, run poisoning + confused-deputy battles against real tool calls. Extend `MCPTarget` beyond static scanning.
   - *Why:* OWASP ASI02 (Tool Misuse & Exploitation) is the hottest agentic threat; Snyk is static-only; nobody does behavioral MCP battles.
   - *Effort:* 2–3 weeks

6. **ASI04 Agentic Supply Chain attacks** ✅ SHIPPED (Aug 23 — targets/supplychain.py: SHA-256 pinning, rug-pull-after-N-calls simulation, diff_registry, PinningDefense closed-loop) — schema manipulation, description deception, permission misrepresentation, registry poisoning.
   - *Why:* OWASP ASI04 is untested by anyone; supply chain attacks against MCP tools and agent registries are emerging threats.
   - *Effort:* 1–2 weeks

7. **ASI08 Cascading Agent Failures** ✅ SHIPPED (Aug 23 — targets/cascade.py: seeded amplification pipeline research→planner→executor→reporter, impact compounding, ValidationDefense closed-loop) — test multi-agent systems for cascade-recovery behavior.
   - *Why:* OWASP ASI08 is untested; complex agent interactions produce unexpected cascading failures.
   - *Effort:* 1–2 weeks

8. **ASI09 Human-Agent Trust Exploitation** ✅ SHIPPED (Aug 23 — targets/trust.py: consent-fatigue approver simulator, compound-action decomposition, hardened composite re-risking defense) — social engineering attacks that exploit human trust in agent outputs.
   - *Why:* OWASP ASI09 is untested; agents that humans trust can be weaponized.
   - *Effort:* 1–2 weeks

9. **ASI10 Rogue Agents** ✅ SHIPPED (Aug 23 — targets/rogue.py: three rotating steganographic exfil channels w/ CovertChannelDetector decode suite, loyal control twin) — detect and test for agents that deviate from their intended behavior.
   - *Why:* OWASP ASI10 is untested; rogue agents are the ultimate failure mode.
   - *Effort:* 1–2 weeks

10. **HarmBench benchmark integration** ✅ SHIPPED (Aug 23 — probes.py: `harmbench_behavioral` pack, 25 behavioral probes across the six HarmBench harm domains (chem/bio, illegal, misinformation, harassment, fraud, cybercrime) each pairing a domain request with a jailbreak frame; plus `jailbreak_personas` pack, 25 DAN-style/developer-mode/no-restrictions persona frames; corpus 102→152 main-corpus probes, threshold test raised to ≥150) — HarmBench-style behavioral coverage is now a first-class probe pack; full external benchmark submission remains future work.
    - *Why:* HarmBench is the gold standard for red teaming evaluation; publishing numbers there establishes credibility.
    - *Effort:* 1–2 weeks

### Phase E2.5 — Research-Derived Differentiators (weeks 8–16)

*Each item traces to a finding in [`docs/LANDSCAPE_2026.md`](./docs/LANDSCAPE_2026.md) that no
competitor has productized. Same playbook as P1–P5b: unclaimed gap + existing seam.*

11. **Adaptive multi-attempt attack mode** ✅ SHIPPED (Aug 23 — attacks/adaptive.py: MultiAttemptAttacker 5-variant rotation, budget always declared in CampaignResult, early-stop, CAISI-grounded) — first-class attempt-budget parameter on
    `BranchingAttacker`/battles; reports always publish attempt budget, per-task ASR
    distribution, and adaptivity level.
    - *Why (LANDSCAPE §4):* NIST CAISI showed known baselines score 11% task-hijacking vs
      **81% for novel adaptive attacks**, and aggregate ASR climbs 57%→80% at 25 attempts.
      Single-shot numbers are now recognized as false assurance — reporting discipline is a moat.
    - *Effort:* 1 week
12. **Metrics productization** ✅ SHIPPED (Aug 23 — reporting/metrics.py: unsafe_action_rate, privilege_escalation_distance BFS, guarded_joint_score quadrants, dual_asr w/ gap, metrics_summary w/ measurement block declaring attempt_budget/adaptivity/judge) — Unsafe Action Rate for CI gates, Privilege Escalation
    Distance per customer tool graph, GUARDEDJOINT-style safety-utility KPI, dual
    ASR-intermediate/ASR-end-to-end reporting.
    - *Why (LANDSCAPE §4.3):* SoK 2603.22928 defines UAR/PED but **no incumbent publishes
      them**; WASP showed end-to-end-only ASR hides 17–86% intermediate compromise
      ("security through incompetence").
    - *Effort:* 2–3 weeks
13. **Protocol-layer security** ✅ SHIPPED (Aug 23 — security/protocol.py: ToolFingerprint sha256 pinning, DriftMonitor rug-pull detection w/ changed/added/removed report, verify_agent_card A2A §8.4 validation incl unsigned-card finding, scan_registry_entries provenance+injection+length findings) — MCP traffic inspection (tool-definition drift detection,
    rug-pull hashing), A2A AgentCard signature validation + trust-tier policy engine.
    - *Why (LANDSCAPE §3):* MCPTox measured up to **72.8% ASR with <3% refusal** across 45
      live servers; A2A v1.0 ships unsigned-by-default cards ("wire format, not a security
      model"). Cloudflare validated demand at the edge only — vendor-neutral inspection incl.
      stdio is an open lane.
    - *Effort:* 3–4 weeks
14. **Compliance evidence automation** ✅ SHIPPED (Aug 23 — reporting/evidence.py: EvidenceArtifact tamper-evident content_hash, build_evidence_pack mapping battles to EU-AI-ACT Art9/Art15 + NIST MEASURE-2/MANAGE-2 + ISO 42001 A.6.1.6 controls, render_evidence_md with retention/covenant notes incl GSA 90-day + insurance ≥24mo, chain_of_custody rolling hash) — map every blocked action to ISO 42001 / EU AI Act
    Art. 9/12/14 / NIST MEASURE-2 control artifacts; pre-built auditor evidence packs;
    tamper-evident signed export (≥24-month retention covenant format).
    - *Why (LANDSCAPE §6–7):* "Continuous compliance evidence wired to runtime decisions" is
      a named commercial white space; cyber-insurance questionnaires now demand per-event
      audit logs and agent identity answers; GSA GSAR 552.239-7001 requires 90-day forensic
      preservation. Archon's audit trail already produces the raw material.
    - *Effort:* 2–3 weeks
15. **Certification alignment** — ✅ SHIPPED (Aug 23, wave 4): `archon_core.reporting.certification`
    — CONTROL_MAP for AIUC-1 (6 categories) + CSA STAR Agentic L2 (5 AICM requirements);
    ConformanceProfile.assess() (satisfied/partial/unmet from evidence-pack controls),
    render_profile_md (readiness % + honest third-party-audit disclaimer),
    certification_readiness aggregate; 18 TDD tests. Formal scheme-body partnership remains item 22.
    - *Why (LANDSCAPE §5):* First certs issued Apr 2026 (UiPath, Cursor, Harvey); both
      schemes explicitly generate EU-AI-Act-conformity-supporting evidence. Positioning
      Archon battles as certification prep is recurring-revenue adjacency.
    - *Effort:* 1–2 weeks (profile) + ongoing

### Phase E3 — Ecosystem & Distribution (months 3–6)

16. **Plugin marketplace directory** — curated `contrib/` gallery indexed in README; CI matrix for community pulls; `archon plugins publish` command.
    - *Why:* Garak and Promptfoo have thriving plugin ecosystems; Archon's five seams need equivalent community engagement.
    - *Effort:* 1–2 weeks

17. **Docs site** — dedicated documentation site (MkDocs or Docusaurus) with tutorials, API reference, and contribution guides.
    - *Why:* Enterprise adoption requires excellent documentation; Garak and Promptfoo have this.
    - *Effort:* 1–2 weeks

18. **Managed cloud control plane** — multi-tenant armor deployments, scheduled continuous battles, alerting on baseline regressions.
    - *Why:* This is the revenue layer over the MIT open core; enterprises want managed security, not self-hosted.
    - *Effort:* 2–3 months

19. **Commercial partnerships** — integrate with NeMo Guardrails, Model Armor, Lakera as validated defense targets; co-marketing opportunities.
    - *Why:* "We validate NeMo" is marketing they can't refuse; partnerships accelerate adoption.
    - *Effort:* ongoing

### Phase E4 — Market Leadership (months 6–12)

20. **Published research** — submit Archon as a research contribution to a top security conference (USENIX Security, IEEE S&P, CCS).
    - *Why:* Academic credibility is the ultimate enterprise signal; Garak and AgentDojo have this.
    - *Effort:* 2–3 months (research paper)

21. **Enterprise features** — RBAC, SSO integration, multi-tenant isolation, SLA guarantees.
    - *Why:* Enterprise procurement requires these features; currently only commercial tools offer them.
    - *Effort:* 2–3 months

22. **Certification program partnership** — extend the E2.5 certification-alignment profile into a formal program with a scheme body, using Archon as the testing backend.
    - *Why:* Certification programs create recurring revenue and market lock-in; AIUC-1 and CSA STAR for Agentic are the live entry points (see item 15).
    - *Effort:* 3–6 months (partnership)

---

## Explicitly descoped (and why)

- **RL-adaptive attack strategies** — deterministic branching + provider-driven mutation covers the practical threat model at a fraction of the cost.
- **Own eval-quality metrics** — DeepEval/RAGAS own that space; Archon's helpfulness regression ("normal user test") covers the security-relevant slice.
- **Becoming a guardrail library** — NeMo/DeepTeam ship DIY guard libraries; Archon ships the *measurable enforcement point* plus the adversary that validates it.
- **Becoming a governance platform** — Obot and Zenity own that space; Archon focuses on security testing.

---

## Enterprise Readiness Gap Analysis

### Engineering maturity (code-quality audit, Aug 23)

| Gap | Severity | Evidence | Closure path |
|---|---|---|---|
| No CI pipeline | 🔴 High | Zero GitHub Actions workflows run the test suite; 892 passing tests are local-only | Phase E0 item 1 |
| No lint/type enforcement | 🟠 Medium | mypy is a dev dep but no ruff config, no pre-commit, no coverage gate; type hints inconsistent | Phase E0 item 1 |
| Legacy packaging baggage | 🟠 Medium | Root install pulls competition stack (`a2a-sdk`, `google-adk`, `google-genai`, `openai`); packages not cleanly separable | Phase E0 item 2 |
| Identity confusion | 🟠 Medium | LICENSE says "Copyright 2025 AgentBeats"; v0.1.0; zero git tags; no CHANGELOG or release process | Phase E0 item 2 |
| SQLite-first persistence | 🟠 Medium | Postgres registry exists but thin production mileage; no schema migrations | Phase E0 item 4 |
| Security tool has no self threat model | 🟠 Medium | HMAC auth shipped, but no fuzzing of the proxy parser, no documented auth boundary, no SECURITY.md/CVE process | Phase E0 item 3 |

**What promptfoo has that Archon lacks** (the honest list): monorepo CI matrix + ~3,000 tests
per commit, signed releases with SBOMs, npm distribution with telemetry, DB-backed shareable
results, versioned docs site, YAML config with JSON-schema editor autocomplete, community
(24k stars, Discord), CVE process. *Enterprises buy operational maturity; researchers buy
capability. Archon currently has only the latter — E0 closes the maturity gap while E1–E4
compound the capability lead.*

### Capability gaps

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
