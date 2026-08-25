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
| Probe corpus + OWASP mapping | 222 probes across 10 packs (all 10 OWASP LLM categories, data-exfil, ANSI exfil, package-hallucination, HarmBench, jailbreak personas, encoding, latent, canaries) + contrib | `packages/archon_armor/probes.py` |
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

*Code-quality audit verdict at audit time: **B+ hackathon, C+ enterprise** — every gap it
named has since been closed by Phases E0/E2.6 (see the gap table below). Current state:
**2,295 passing tests**, CI-enforced.*

1. **CI pipeline ✅ SHIPPED (Aug 23 — .github/workflows/ci.yml test matrix py3.11-3.13 + ruff + --cov-fail-under=85 gate at 93% actual + release.yml tags/SBOM)** — GitHub Actions: test matrix (py3.11/3.12/3.13), ruff + mypy strict on
   `packages/`, coverage gate ≥85%, release workflow with tags + SBOM.
   - *Why (at audit time):* All tests passed locally but nothing enforced that on PRs. This was the single
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

1. ~~**Full-pipeline benchmark run**~~ ✅ **SHIPPED (Aug 24)** — live Gemini (`gemini-3.5-flash-lite`) Tier-3 run published in RESULTS.md: full-pipeline ASR **27.2%** vs deterministic-tier 66.7% (27 blocked pre-upstream, 54 reached the model, 22 complied); includes event-loop regression fix in llm_tier.py (+1 test).
   - *Why:* The deterministic-tier ASR (66.7%) is honest but incomplete. Enterprises need to see the full pipeline's ASR to trust the defense.
   - *Effort:* 1–2 days (infrastructure: need LLM API access)

2. ~~**Attacker diversity — local vLLM**~~ ✅ **SHIPPED (wave 8)** — providers/vllm.py VllmProvider preset + vllm_from_env, docs-site/local-models.md, examples/vllm.yaml (schema-valid); Claude/Gemini/Gemma native options shipped earlier.
   - *Why:* Garak and Promptfoo support multiple providers. Claude is covered natively; vLLM is free via its OpenAI-compat server + `OpenAICompatProvider` (zero new code).
   - *Effort:* 2–3 days

3. **Live demo + docs** — one Docker + Postgres + Helm template, one YouTube walkthrough. Makes it usable, credible, enterprise-pilot-ready.
   - *Why:* The hackathon demo is time-limited; a persistent demo is what enterprises actually evaluate.
   - *Effort:* 3–5 days

4. ~~**Probe corpus 150+**~~ ✅ **SHIPPED** (waves 5+7: HarmBench behavioral ×25, jailbreak personas ×25, data-exfiltration ×50 packs; corpus 102→**222** (waves 7+11), ahead of Garak's 195; threshold test ≥200) — adversarial benchmark suites as packs; community pack loader keeps this crowd-solvable.
   - *Why:* Corpus breadth was Archon's weakest attack-side row. Community pack loader makes this crowd-solvable.
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

### Phase E2.6 — OWASP-Aligned Hardening (weeks 4–8)

> Derived from the Aug 2026 OWASP *Red-Teaming Solutions Taxonomy v1.0* and
> *State of Agentic AI Security & Governance v2.01* deep review (see
> `docs/LANDSCAPE_2026.md`). Each item closes a gap the OWASP criteria name
> that Archon's Aug-23 honest self-assessment confirmed.

23. ~~**One-click purple runs**~~ ✅ **SHIPPED** (wave 5) — `archon purple --policy-a A --policy-b B` attacks two policy versions with the same probe set and emits the compare verdict in one command (fuses `battles` + `compare`; taxonomy Purple/"one-click purple runs" + "map red scenarios to blue controls").
    - *Effort:* ≤2 days

24. ~~**Scheduled fuzzing + autonomous red bots**~~ ✅ **SHIPPED** (wave 5) — nightly CI workflow running the seeded fuzz corpus against armor plus an `archon bot` continuous-probe loop against a live target (taxonomy Red/Operate: "autonomous red bots", "continuous prompt fuzzing").
    - *Effort:* ≤2 days

25. ~~**Kill-switch drill**~~ ✅ **SHIPPED** (wave 5) — `archon kill-switch --agent X` revokes identity, drops subscriptions and denies egress in one atomic action; measures MTTC (State of Agentic survival capability #5: "a kill switch that works at agent speed rather than committee speed").
    - *Effort:* ≤2 days

26. ~~**Beyond-ASI attack patterns**~~ ✅ **SHIPPED** (wave 5) — targets for reconnaissance/discovery, config-tampering persistence, and staged payload delivery — the three patterns OWASP itself flags as uncovered by ASI01–10.
    - *Effort:* 3–5 days

27. ~~**Plan-divergence detection**~~ ✅ **SHIPPED** (wave 5) — trajectory-level monitoring comparing declared intent vs executed actions from trace spans (State of Agentic runtime-governance capability #1; natural extension of `trace_driven`).
    - *Effort:* ~1 week

28. **External validation target** ⏸️ **DEFERRED** (post-hackathon; needs repo clone + adapter research) — integrate the OWASP-referenced FinBot CTF (Apache-2.0, self-hostable) as an adapter target so published numbers gain third-party validation.
    - *Effort:* ~1 week

29. ~~**Nonce store for HMAC replay window**~~ ✅ **SHIPPED** (wave 5) — closes the documented SECURITY.md limitation (same-signature replay succeeds within ±300s); update auth-boundary tests to the new behavior.
    - *Effort:* ≤2 days

30. ~~**Docs site + advisory program**~~ ✅ **SHIPPED** (wave 5) — MkDocs site generated from existing markdown; `security@` contact + coordinated advisory publishing (enterprise rating gap).
    - *Effort:* 1 week

### Phase E2.7 — Submission Package & Enterprise Quick Wins (pre-deadline sprint) — **COMPLETE**

> Sources: enterprise A+ ladder analysis (Aug 24) against docs/LANDSCAPE_2026.md RFP essentials; hackathon bonus-point list. All items are deploy-independent.

31. ~~**Devpost submission package**~~ ✅ **SHIPPED** (wave 6) — `DEVPOST.md`: project description, what-it-does, how-we-built-it, judging-criteria alignment copy, architecture description ready to paste into Devpost.
32. ~~**Demo video script**~~ ✅ **SHIPPED** (wave 6) — `DEMO_SCRIPT.md`: beat-by-beat ~4-min script with exact commands, expected outputs, and screenshot mapping (Cloud Trace span tree = primary judge proof).
33. ~~**Blog/social post**~~ ✅ **SHIPPED** (wave 6) — public post draft tagged #AllThingsAgenticHackathon (bonus points): the closed-loop security story.
34. ~~**Gemma provider option**~~ ✅ **SHIPPED** (wave 6) — `ARCHON_ATTACK_PROVIDER_KIND=gemma` maps to the Gemini OpenAI-compat endpoint with a Gemma model default (hackathon bonus: Gemma integration).
35. ~~**Signed releases**~~ ✅ **SHIPPED** (wave 6) — cosign/Sigstore keyless signing step in release.yml; artifacts published with signatures (supply-chain trust gate for hyperscaler buyers).
36. ~~**Kill-switch CI drill**~~ ✅ **SHIPPED** (wave 6) — scheduled workflow running an automated kill-switch drill with MTTC assertion (OWASP survival capability: "tested monthly at agent speed").
37. ~~**Shadow mode**~~ ✅ **SHIPPED** (wave 6) — armor evaluates every defense layer and logs would-block verdicts without enforcing, so enterprises measure block rates on mirrored traffic before taking enforcement risk.
38. ~~**Full-pipeline benchmark tier**~~ ✅ **SHIPPED** (wave 6) — env-gated LLM-layer benchmark run in archon_benchmarks; publishes real full-pipeline ASR the moment an API key is present (closes the deterministic-tier-only credibility gap).
39. ~~**Multi-attempt benchmark series**~~ ✅ **SHIPPED** (wave 6) — adaptive attacker (CAISI methodology, attempt budget ≤25) over the AgentDojo harness; publishes attempt-budget curves per RESULTS.md methodology commitments.
40. ~~**Macaroon-style attenuating tokens**~~ ✅ **SHIPPED** (wave 6) — caveat-chain verification for agent credentials (delegation narrowing, offline subsumption checks); nobody in the landscape ships this.
41. ~~**Google ADK adapter**~~ ✅ **SHIPPED** (wave 6) — target adapter wrapping an ADK agent as a battle target (also strengthens the mandatory Google-Agent-Framework requirement).
42. ~~**GitHub Pages docs workflow**~~ ✅ **SHIPPED** (wave 6) — publishes the existing MkDocs site on push (docs site goes live without any GCP deploy).
43. ~~**Multi-tenancy v1**~~ ✅ **SHIPPED** (wave 6) — tenant-scoped results store and registry scoping (`tenant_id` on battles/results/agents); first step toward the biggest enterprise RFP gap.
44. ~~**FinBot CTF adapter**~~ ✅ **SHIPPED** (wave 7 adapter; Aug 24 sim extended to 7 challenge-grounded vectors from the real YAML definitions — shell-shock foot-in-the-door RCE, scorched-earth poisoned-tool wipe, recon policy leak, gradual status flip — each with paired defense + closed-loop tests).

### Phase E2.8 — Evidence & Hardening Sprint (Wave 7, pre-deadline)

*Sources: RESULTS.md "follow-up benchmark series" promise; methodology commitment #4 (utility cost); competitor gap-closure plan (garak breadth / LLM-brain attackers / promptfoo DX); Devpost architecture-diagram requirement.*

45. ~~**Per-target ground-truth benchmark series**~~ ✅ **SHIPPED** (wave 7 — target_series.py: adaptive attacker (budget 3, seed 42) vs all 11 live targets; aggregate ASR 81.8% (27/33) from state-diff ground truth, zero LLM calls; published in RESULTS.md) — run the adaptive attacker against every live attack target (sandbox banking transfer, memory poisoning, multi-agent trust boundary, MCP rug-pull, supply-chain rug-pull, cascade, trust exploitation, rogue stego, recon/config-tamper/staged-payload gaps); `attack_success` comes from state diffs, so these are real ASR numbers with zero LLM calls. Publish in `RESULTS.md` (fulfills the existing promise there).
46. ~~**False-positive-rate publication**~~ ✅ **SHIPPED** (wave 7 — 0/12 benign canaries blocked — deterministic-tier over-refusal rate 0.0%, published in RESULTS.md (methodology commitment #4 closed)) — measure the deterministic tier's over-refusal rate on the 12 benign canaries (`harmless_helpfulness` pack); completes methodology commitment #4.
47. ~~**Applied-metrics exemplar**~~ ✅ **SHIPPED** (wave 7 — UAR 0.75 / PED 4 hops / GUARDEDJOINT quadrants worked example on the banking sandbox, published in RESULTS.md) — compute UAR / Privilege Escalation Distance / GUARDEDJOINT quadrants on the sandbox banking scenario and publish as a worked example in `RESULTS.md`.
48. ~~**Identity v2: signed agent credentials**~~ ✅ **SHIPPED** (wave 7 — security/identity.py: CredentialStore sqlite + ed25519 sign_request_ed25519 + Ed25519Verifier drop-in via create_app(identity=...); cryptography dep added; 23 tests) — ed25519-signed per-agent identities issued and verified by armor (replacing shared HMAC secrets); pairs with the wave-6 attenuating-token caveats module.
49. ~~**Purple --baseline Policy-CI gate**~~ ✅ **SHIPPED** (wave 7 — purple.py save_baseline/load_baseline/compare_to_baseline + CLI --save-baseline/--baseline; --ci exits 1 on regression vs baseline) — commit a baseline verdict file; `archon purple --ci --baseline FILE` fails when any probe regresses vs baseline (merge-blocking defense regression gate).
50. ~~**FinBot CTF adapter**~~ ✅ **SHIPPED** (wave 7 — finbot-ctf cloned (gitignored) + targets/finbot.py FinBotTarget wrapping the CTF with offline sim fallback; 20 tests incl skipif-guarded live integration) — clone the OWASP-referenced repo, wrap it as a battle target for third-party-validated numbers (closes deferred item 44 if feasible pre-deadline).
51. ~~**Community scaffolding**~~ ✅ **SHIPPED** (wave 7 — CONTRIBUTING.md, CODE_OF_CONDUCT.md (Contributor Covenant), feature_request template, test_community guards; tag v1.0.0 pushed to exercise release.yml+cosign) — CONTRIBUTING.md, CODE_OF_CONDUCT.md, feature-issue template; tag v1.0.0 to exercise release.yml + cosign end-to-end.
52. ~~**Architecture diagram**~~ ✅ **SHIPPED** (wave 7 — docs-site/architecture-diagram.md — 3 Mermaid diagrams (request flow, closed-loop red/blue, GCP topology); Devpost image slot filled) — Mermaid diagram in docs-site (renders on GitHub); fills the Devpost image slot.
53. ~~**Docs-site expansion**~~ ✅ **SHIPPED** (wave 7 — docs-site/tutorials/ — index + 8 per-target tutorials w/ verified uv run snippets and ASI mappings; mkdocs nav updated) — tutorial pages per attack target ("run your first memory-poisoning battle").
54. **GitHub Pages enablement** — *user-side*: flip the 2-click repo setting (docs.yml already shipped, item 42).

### Phase E2.9 — External Benchmark Expansion (Wave 9, pre-deadline)

*Sources: benchmark-gap analysis vs garak/promptfoo/PyRIT dataset inventories; LANDSCAPE_2026 §4 benchmark adoption table; NIST CAISI cyber-evals methodology review (cloned, capability-axis — cited not run).*

55. ~~**InjecAgent benchmark harness**~~ ✅ **SHIPPED** (wave 9 — injecagent.py harness + committed fixture; full 1,054-case deterministic run published in RESULTS.md (0% block / 100% ASR — embedded-polite injections need LLM layers, consistent with AgentDojo wrappers)) — — run the InjecAgent corpus (direct + indirect injection during tool use, ground-truth tool-call labels → deterministic grading, zero LLM-judge cost); publish block rate / ASR in RESULTS.md alongside AgentDojo. Second published agentic benchmark kills the "one-off" objection.
56. ~~**tau-bench pass^k consistency metric**~~ ✅ **SHIPPED** (wave 9 — passk.py over per-target series seeds 42/43/44: pass^k 11/11 = 1.0, zero seed-inconsistency; published in RESULTS.md) — — re-run the per-target series across k seeds and report pass^k consistency (models drop hard on this metric per tau-bench); reuses existing target_series infrastructure.
57. ~~**R-Judge benchmark harness**~~ ✅ **SHIPPED** (wave 9 — rjudge.py w/ heuristic + LLM-judge paths; heuristic agreement published 47.6% acc / F1 0.063; live Gemini-judged run completed same day) — real-world unsafe agent trajectories (569 records) scored via the provider-seam LLM judge; env-gated live run + offline stub tests.
58. ~~**Dual-ASR formal labeling + NIST CAISI alignment citations**~~ ✅ **SHIPPED** (wave 9 — strict-ASR section formally labeled dual ASR per WASP; NIST CAISI methodology-alignment section added to RESULTS.md) — — label the existing evasion-vs-strict-ASR results as dual ASR per WASP; cite NIST CAISI evaluation practice (multi-attempt budgets, Inspect harness) as methodology alignment in RESULTS.md. Doc-only, zero cost.
59. ~~**Multi-provider presets**~~ ✅ **SHIPPED** (wave 9 — provider_from_env kinds openrouter (openrouter.ai/api/v1) + nvidia (integrate.api.nvidia.com/v1), model-overridable via env) — — OpenRouter (`https://openrouter.ai/api/v1`) and NVIDIA NIM (`https://integrate.api.nvidia.com/v1`) OpenAI-compatible presets in `provider_from_env` (kind `openrouter` / `nvidia`), mirroring the vLLM preset pattern; enables multi-provider benchmark runs without code changes.
60. **AgentHarm benchmark harness** *(stretch)* — harmful-behavior tasks with jailbreaks (440-task extended set), judge-scored; only if quota and time allow after 55–59.

### Phase E2.10 — Augustus-Derived Hardening (Wave 10)

*Sources: deep engineering comparison vs praetorian-inc/augustus (cloned Aug 24; 201K Go LOC, 4,057 test funcs, 13 CI workflows, network-level MCP transport attacks). Augustus is the strongest offense-only rival; these items adopt its best ideas and pair them with Archon's uncontested closed-loop defense verification.*

61. ~~**MCP transport-layer attack target**~~ ✅ **SHIPPED** (wave 10 — targets/mcp_transport.py: DnsRebindingTarget TOCTOU rebind+exploit ARCHON-MCP-DNS-77, SessionHijackTarget foreign/stale-token privilege use ARCHON-MCP-SESS-88, OffPathAttackerTarget credential-exfil egress check ARCHON-MCP-OFFPATH-99; paired defenses pin/bind/allowlist; 22 TDD tests incl closed-loop)
62. ~~**AI code-review CI workflow**~~ ✅ **SHIPPED** (wave 10 — .github/workflows/ai-review.yml: PR-triggered Claude review posting automated comments; graceful no-op without ANTHROPIC_API_KEY)
63. ~~**Prometheus `/metrics` endpoint on archon-armor**~~ ✅ **SHIPPED** (wave 10 — archon_armor/metrics.py ArmorMetrics stdlib collector: per-agent request/blocked counters + latency histogram w/ standard buckets, thread-safe; wired into create_app GET /metrics text exposition)
64. ~~**YAML declarative probe packs**~~ ✅ **SHIPPED** (wave 10 — archon_armor/yaml_packs.py load_yaml_pack/load_yaml_dir/register_yaml_packs idempotent; contrib/yaml/example_pack.yaml 6 reference-blocked probes; 18 TDD tests)
65. ~~**Supply-chain CI hygiene**~~ ✅ **SHIPPED** (wave 10 — secrets-scan.yml high-signal pattern scan failing on findings; verify-pins.yml exact-pin enforcement on runtime deps + uv.lock freshness)

### Phase E2.11 — Competitor-Mined Completion Wave (Wave 11)

Source: three-way improvement mining across promptfoo/augustus/agent-scan (DX + product), garak/PyRIT (attacks), NeMo/deepeval/deepteam/ragas (defense + eval). 24 candidates, all TDD.

**Tier 1 — quick wins (items 66–77):**

66. ~~**Tool-call schema validation rail**~~ ✅ **SHIPPED (wave 11)** — fail-closed validation of emitted tool calls against declared JSON schemas (NeMo IORails pattern); biggest remaining defense gap.
67. ~~**Policy Puppetry converter**~~ ✅ **SHIPPED (wave 11)** — fake policy/config XML framing exploiting system-policy deference (PyRIT); deterministic, zero LLM cost.
68. ~~**Token smuggling converters**~~ ✅ **SHIPPED (wave 11)** — Unicode variation-selector / ASCII-smuggler encodings invisible to moderation but decoded by tokenizers (PyRIT).
69. ~~**SHIFT_DETECTED early-stop**~~ ✅ **SHIPPED (wave 11)** — behavior-shift termination for multi-turn attackers (deepteam progression pattern); cleaner ASR-vs-budget curves.
70. ~~**`/v1/checks` sidecar endpoint**~~ ✅ **SHIPPED (wave 11)** — validate messages without proxying (NeMo server/api.py pattern); adoption unlock for teams that can't route all traffic through armor.
71. ~~**Ensemble score aggregation**~~ ✅ **SHIPPED (wave 11)** — AND/OR/MAJORITY composites over regex + LLM judges (PyRIT aggregator patterns); cuts false negatives.
72. ~~**ANSI escape exfil probes**~~ ✅ **SHIPPED (wave 11)** — terminal escape injection pack (garak ansiescape).
73. ~~**Hidden-Unicode tag-char scanner**~~ ✅ **SHIPPED (wave 11)** — Cf/Cc detection incl. U+E0000 tag-sequence decoding (agent-scan W021 upgrade).
74. ~~**Agent-loop detection metric**~~ ✅ **SHIPPED (wave 11)** — zero-cost loop scoring from trace spans: identical-call repetition, reasoning stagnation, DFS back-edge cycles (deepeval).
75. ~~**Typed MetricOutputType contract**~~ ✅ **SHIPPED (wave 11)** — declarative judge output types + auto Cohen's-kappa agreement (ragas base.py pattern).
76. ~~**Package-hallucination probes**~~ ✅ **SHIPPED (wave 11)** — slop-squatting code-gen test mapped to the supply-chain pinning target (garak packagehallucination).
77. ~~**Harm-taxonomy YAML layer**~~ ✅ **SHIPPED (wave 11)** — severity-weighted reporting via structured harm definitions w/ 1–5 rubrics (PyRIT harm_definition).

**Tier 2 — medium lifts (items 78–85):**

78. ~~**SARIF output**~~ ✅ **SHIPPED (wave 11)** ⭐ — `archon results --sarif`; neither augustus nor any competitor emits SARIF; unlocks GitHub Code Scanning natively — category first.
79. ~~**Static self-contained HTML report**~~ ✅ **SHIPPED (wave 11)** — `archon results --html`, single-file inline-CSS (augustus html.go pattern); share tokens work on any static host.
80. ~~**`archon discover`**~~ ✅ **SHIPPED (wave 11)** — walk Claude Desktop/Cursor/VSCode/Gemini CLI config paths per-OS, list MCP servers/skills, one-command scan (agent-scan well_known_clients port).
81. ~~**Skill scanning**~~ ✅ **SHIPPED (wave 11)** — SKILL.md injection/secrets/remote-fetch checks (agent-scan E004–E006/W007–W014); entire threat category added.
82. ~~**Buff layer**~~ ✅ **SHIPPED (wave 11)** — composable perturbation wrappers giving N_probes × N_buffs multiplicative coverage with provenance (garak buffs/base.py).
83. ~~**Judge-calibration harness**~~ ✅ **SHIPPED (wave 11)** — ScorerEvaluator-style accuracy/F1/Krippendorff α vs human-labeled sets; productizes R-Judge agreement into a judge-quality report.
84. ~~**Run-history diff views**~~ ✅ **SHIPPED (wave 11)** — timestamped immutable run snapshots + regression diffing over results store (deepeval local_store pattern).
85. ~~**Toxic-flow capability graph + cross-server shadowing**~~ ✅ **SHIPPED (wave 11)** — untrusted×sensitive×destructive combination analysis + E002 tool-shadowing flags (agent-scan W015–W020/E002).

**Tier 3 — larger (items 86–89):**

86. ~~**Coding-agent target suite**~~ ✅ **SHIPPED (wave 11)** — verifier-sabotage, automation-poisoning/delayed-CI-exfil, procfs-credential-read, network-egress-bypass, terminal-output-injection (promptfoo codingAgents.ts subset).
87. ~~**Streaming rolling-buffer output rails**~~ ✅ **SHIPPED (wave 11)** — RollingBuffer/ChunkBatch design + tests, prerequisite for SSE so streamed jailbreaks can't bypass the output layer (NeMo buffer.py).
88. ~~**BEAST adversarial suffixes**~~ ✅ **SHIPPED (wave 11)** — beam-search suffix generation without logprobs (garak suffix.py, arXiv 2402.15570) + cached-GCG variant.
89. ~~**Compliance-card report module**~~ ✅ **SHIPPED (wave 11)** — framework compliance cards w/ pass-rate rollups (promptfoo FrameworkCompliance pattern) rendered from evidence packs.

#### Phase E3 — Research-Derived Frontier (post-hackathon, weeks 1–6)

> Sources: docs/new_research.md (12-paper deep read, Aug 25, arXiv-verified) + model-sensitivity study (RESULTS.md).

66. ~~**PIMiner hierarchical-memory attacker upgrade**~~ ✅ **SHIPPED (wave 12)** — RunMemory intra-dataset Curate store (20K cap), StrategyLibrary markdown files, LLM Top-K router w/ cold-start fallback, Digester classify-by-mechanism protocol; ablation-grounded (+17.8–19.8 pts avg ASR per PIMiner Table).
67. ~~**Action-time policy reminder DefenseLayer**~~ ✅ **SHIPPED (wave 12)** — runtime interjection at action boundary (NOT system prompt), REDAgentBench −74.19pp evidence, matched-pair replay w/ placebo control.
68. ~~**Property-tagged metrics (SA/TA/AA/DI)**~~ ✅ **SHIPPED (wave 12)** — tag findings by violated property (Source Authorization / Task Alignment / Action Alignment / Data Isolation) per arXiv:2607.22024; reports decompose compromises by property.
69. ~~**StepJack deterministic CUA target**~~ ✅ **SHIPPED (wave 12)** — page-chain simulator w/ env-state checkers + per-step compliance βᵢ diagnostics; GPL dataset loader (cache→network→fixture); DSP defense layer port.
70. ~~**APC composition-closure caveats (C2b)**~~ ✅ **SHIPPED (wave 12)** — prohibit_pair/prohibit_tuple caveats + session prior-action registry held outside the model; Blast Radius Monotonicity property test.
71. ~~**Skill-scan lifecycle stages**~~ ✅ **SHIPPED (wave 12)** — Storage (manifest consistency declared-vs-body), Retrieval (cross-file similarity clustering for Sybil/stuffing), Evolution (version-diff escalation) per SkillSec-Eval.
72. ~~**Prompt-as-Rule LLM audit tier**~~ ✅ **SHIPPED (wave 12)** — opt-in NL-criteria tier over mcp_scan regexes w/ mandatory exclusion conditions + network-reachability filtering (AI-Infra-Guard discipline).

### Phase E4 — Universal Benchmark Coverage (wave 13, Aug 25) — ✅ ALL SHIPPED

Goal: run every benchmark competitors and frontier papers use, fully reproducible
(cache → network → committed fixture loaders, deterministic grading first, LLM tiers env-gated).
All code lives in `packages/archon_benchmarks/`.

73. ~~**SkillTrustBench**~~ (5,520-case skill-supply-chain dataset, HF cuhk-zhuque/SkillTrustBench) — validates skill_scan lifecycle stages vs ground-truth labels
74. ~~**XSTest**~~ (250 over-refusal contrast prompts) — citable false-positive/over-refusal benchmark upgrading the FPR claim
75. ~~**Agent-SafetyBench**~~ (2,000 cases, 10 risk categories) — deterministic reference-pipeline block-rate grading
76. ~~**BIPIA**~~ (web/email indirect injection) — maps onto latent-injection machinery
77. ~~**AgentHarm**~~ (440 tasks) — refusal-grading deterministic tier + env-gated LLM judge
78. ~~**HarmBench full behaviors**~~ (400 behaviors vs 25-probe pack) — corpus expansion benchmark module
79. ~~**WASP dual-ASR tagging**~~ on AgentDojo runs (ASR-intermediate vs end-to-end reporting layer)
80. ~~**StrongREJECT**~~ (rubric judge; deterministic keyword fallback + env-gated LLM rubric)
81. ~~**IPIArena loader**~~ (PIMiner's training/test arena; fixture fallback w/ honest availability note)
82. ~~**ASB loader**~~ (agent security bench used by AgentFlow/APC)
83. ~~**MCPTox-style live-MCP probing wrapper**~~ over mcp_live (env-gated live tier + offline emulation)
84. ~~**tau-bench task loader**~~ (deterministic policy-probe tier over public tasks; full user-sim harness documented as stretch)

## Phase E3 — Ecosystem & Distribution (months 3–6)

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

### Engineering maturity (code-quality audit, Aug 23 — **all six gaps CLOSED** by Phases E0/E2.6)

| Gap | Severity at audit | Status | Closed by |
|---|---|---|---|
| No CI pipeline | 🔴 High | ✅ CLOSED — ci.yml runs lint + py3.11–3.13 matrix + coverage gate (93% actual) on every push; release.yml tags/SBOM; fuzz.yml nightly | E0 item 1 |
| No lint/type enforcement | 🟠 Medium | ✅ CLOSED — ruff enforced in CI, pytest-cov `--cov-fail-under=85` gate | E0 item 1 |
| Legacy packaging baggage | 🟠 Medium | ✅ CLOSED — `competition` extra isolates a2a-sdk/google-adk/google-genai/openai out of core deps | E0 item 2 |
| Identity confusion | 🟠 Medium | ✅ CLOSED — MIT / Archon Contributors, v1.0.0, CHANGELOG.md | E0 item 2 |
| SQLite-first persistence | 🟠 Medium | ✅ CLOSED — SchemaMigrator versioned migrations + ResultsStore + Postgres integration job in CI | E0 item 4 |
| No self threat model | 🟠 Medium | ✅ CLOSED — SECURITY.md + 200-iteration fuzz invariant + auth-boundary tests + nonce store closing the replay window | E0 item 3 + E2.6 item 29 |

**What promptfoo has that Archon lacks** (the honest list, updated Aug 23 post-E2.6):
signed releases with SBOMs *(release workflow ships; signing pending)*, npm telemetry,
DB-backed shareable results *(ResultsStore + share tokens shipped)*, ~~versioned docs
site~~ *(mkdocs site now generated from the same markdown)*, YAML JSON-schema editor
autocomplete, community (24k stars, Discord), CVE process *(SECURITY.md disclosure
process + advisory template shipped; formal CVE numbering authority pending)*.
*Enterprises buy operational maturity; researchers buy capability. Archon now has both
the capability lead and the operational baseline — remaining deltas are community scale
and formal certification, not engineering hygiene.*

### Capability gaps

| Gap | Severity | Evidence | Closure path |
|---|---|---|---|
| ~~Probe corpus breadth vs Garak (195)~~ | ✅ CLOSED | **222 probes** vs 195 — largest open agentic-security corpus (waves 7+11: data-exfil, ANSI exfil, package-hallucination packs) | Done; contrib gallery keeps growing it |
| ~~Provider diversity (local vLLM)~~ | ✅ CLOSED | VllmProvider preset + docs + schema-valid example (wave 8); Claude/Gemini/Gemma/OpenRouter/NVIDIA presets shipped | Done |
| Live demo + persistent docs | 🟠 Medium | mkdocs site shipped; GitHub Pages enablement is user-side 2-click | Enable Pages + YouTube walkthrough |
| ~~Full-pipeline benchmark (LLM layers)~~ | ✅ CLOSED | Tier-3 published: live Gemini full-pipeline ASR 27.2% vs deterministic 66.7% | Done |
| ~~ASI04/ASI08/ASI09/ASI10 coverage~~ | ✅ CLOSED | supplychain/cascade/trust/rogue targets shipped (waves 1–2); ASI05 closed by `targets/code_exec.py` (sleeper-agent/sandbox-escape/destructive battles) — **10/10 ASI full** | Done |
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
| Probe corpus | 200+ | **222** ✅ |
| Published benchmarks | 3+ (AgentDojo, HarmBench, custom) | **9+** ✅ (AgentDojo deterministic + Tier-3, InjecAgent, pass^k, R-Judge heuristic+LLM, strict-ASR, per-target series, FPR, FinBot suite) |
| Enterprise pilots | 5+ | 0 |
| Community plugins | 50+ | 18 (contrib/) |
| Documentation pages | 100+ | ~20 |
| CI/CD integrations | GitHub Actions, GitLab CI, Jenkins | GitHub Actions (via --ci) |

---

*Maintained alongside code on `hackathon-v2`. Bump version/date on substantive edits.*
