# Archon — Current Status

> **Last updated:** August 25, 2026 · **Branch:** `hackathon-v2` · **Suite:** 1941 passed / 3 skipped
> This is the single source of truth for "where is the project right now." Historical docs live in `docs/archive/`.

## What Archon is

The only open platform where an **adaptive attacker and a measurable defense fight in the same
loop** — attacks your agent, deploys a shield in front of it, re-attacks to *prove* the shield
works, and exports every verdict as OWASP-mapped audit evidence. MIT-licensed, self-hostable,
vendor-neutral.

## Shipped capabilities (all test-enforced)

| Capability | Entry point |
|---|---|
| 8-layer defense pipeline (deterministic tier → LLM layers) | `packages/archon_core/defenses/layers.py` |
| Adaptive multi-turn attacker (Hydra-style fan-out/pivot/prune, deterministic verdicts) | `archon battle --target URL --goal G --ci` |
| Runtime defense proxy (OpenAI-compatible; drop-in via `OPENAI_BASE_URL`) | `packages/archon_armor/` · HMAC identity, rate limiting, per-agent policy, output redaction |
| Probe corpus: 222 probes across 10 packs (OWASP LLM Top-10 ×56, data exfiltration ×50, ANSI escape exfiltration ×10, package hallucination ×10, HarmBench behavioral ×25, jailbreak personas ×25, encoding evasion ×15, latent injection ×15, benign canaries ×12, core ×4) + 18 contrib probes | `archon plugins --ci` |
| MCP security: static tool-poisoning scan + live behavioral probing | `archon scan-mcp --url ... --probe-tool NAME` |
| Third-party guardrail validation ("we validate them") | `archon scan --target <guardrail-url>` |
| Pluggable external defenses (NeMo / Model Armor / Promptfoo Guardrails as DefenseLayers) | `ExternalGuardrailLayer` |
| Observability: real OTel SDK → Cloud Trace, PII-scrubbed, immutable audit trail | `ARCHON_OTEL_EXPORTER=otlp` |
| Governance: versioned policies, Postgres registry, append-only audit | `ARCHON_DATABASE_URL` |
| Policy-CI: defense regression gates + fleet gate | `archon scan --gate-baseline` · `archon fleet --ci` |
| Compliance evidence reports (OWASP-mapped HTML/MD) | `archon report` |
| Evidence-derived severity scoring (CVSS-style 0–10, vector strings, bands) in every battle summary + report | `reporting/severity.py` |
| Live tool-execution battles: sandbox targets, real tool calls, ground-truth env-diff verification | `targets/sandbox.py` |
| Trace-driven attack generation: mines span streams into targeted evasion/injection/exploit attacks | `attacks/trace_driven.py` |
| ASI07 multi-agent trust-boundary attacks: coordinator trusts worker output — smuggled directives cross the boundary; closed-loop vs sanitized variant | `targets/multiagent.py` |
| Comparison engine: A-vs-B battle diff (rates, per-category deltas, probe-level regressions, verdict) with CI gate | `archon_armor/compare.py`, `archon compare` |
| Checkpoint/resume for long battles: crash-safe per-probe persistence, resume skips completed probes | `archon_armor/checkpoints.py`, `archon scan --checkpoint/--resume` |
| Web UI fleet dashboard: zero-dependency dark-theme UI at `/ui`, agents + policies + recent battles, 10s auto-refresh | `archon_armor/ui.py`, `archon ui` |
| Contrib pack gallery: finance/healthcare/devops probe packs, namespaced, auto-discovered via `ARCHON_CONTRIB_DIR` | `contrib/` |
| Distribution: Homebrew formula + npm wrapper (`npx archon-security`) around the uv-installed CLI | `packaging/homebrew/`, `packaging/npm/` |
| Live memory/vector-store poisoning: real store manipulation, benign-query retrieval hijack, remediation loop | `targets/memory.py` |
| Benchmark harness: AgentDojo v1, all 27 published injection tasks | [`RESULTS.md`](./RESULTS.md) — deterministic-tier ASR 66.7% / block 33.3% |
| Packaging: wheel, non-root Dockerfile, docker-compose, Helm chart | `deploy/helm/archon-armor/` |

## Engineering maturity (Aug-23 audit → **all six gaps CLOSED**, Aug 24)

The Aug-23 audit verdict was **B+ hackathon, C+ enterprise**. Every gap it named is now
closed by Phases E0/E2.6: CI pipeline (py3.11–3.13 matrix + ruff + ≥85% coverage gate,
93% actual), MIT/Archon identity with v1.0.0 tag + CHANGELOG + cosign-signed SBOM
releases, competition deps isolated behind an extra, schema migrations + durable results
store + Postgres CI job, SECURITY.md threat model + fuzz invariant + nonce-store replay
protection. Remaining honest deltas vs promptfoo are community scale and formal CVE
numbering authority — not engineering hygiene.

- Multi-tenancy v2: TenantStore (tenants + agent enrollment, strict isolation), X-Tenant-ID enforcement middleware (403 cross-tenant), SCIM v2 /scim/v2 provisioning router (CRUD+filter+PATCH, 409/404 envelopes), OIDC SSO verifier (RS256 JWKS w/ cache TTL, exp/iss/aud checks).

## Verified competitive position

Code-verified against 9 competitor repos on Aug 23, 2026 (refreshed Aug 24 at 1,941
tests) — full analysis in [`COMPETITIVE_ANALYSIS.md`](./COMPETITIVE_ANALYSIS.md).
Headline: promptfoo's adaptive multi-turn brains run cloud-side; garak is multi-turn
now but scanner-only with no defense evaluation; PyRIT has zero compliance mapping;
NeMo defends but cannot self-validate; Snyk agent-scan never executes attacks and
analyzes behind a closed API. On the seven agentic attack-surface dimensions
(COMPETITIVE_ANALYSIS §5.1 — live tool-state attacks, memory poisoning, ASI07 trust
boundaries, derived severity, trace-driven attack generation, policy comparison,
fleet UI), Archon is the only project best-in-class on all of them; no competitor
holds more than one partial. Nobody else combines adaptive offense + shippable
defense + adversarial proof.

## OWASP Agentic Top-10 Coverage

| OWASP Risk | ID | Coverage | Status |
|---|---|---|---|
| Agent Goal Hijack | ASI01 | ✅ Full | Core attack surfaces + L0–L4 defenses |
| Tool Misuse & Exploitation | ASI02 | ✅ Full | MCP static scan + live behavioral probing + sandbox targets |
| Agent Identity & Privilege Abuse | ASI03 | ✅ Full | HMAC + ed25519 identity v2, attenuating tokens, kill-switch revocation, trust-exploitation target |
| Agentic Supply Chain Compromise | ASI04 | ✅ Full | Rug-pull-after-N-calls simulation, SHA-256 pinning, PinningDefense closed-loop |
| Unexpected Code Execution | ASI05 | ✅ Full | `targets/code_exec.py`: SleeperAgentTarget (persistent payload → privileged read → execution, FinBot sleeper-agent pattern), SandboxEscapeTarget (os.system/subprocess/workspace-path escape vectors), DestructiveCommandTarget (mass purge without approval); paired defenses (write-time quarantine, command allowlist, approval gate); 26 tests |
| Memory & Context Poisoning | ASI06 | ✅ Full | Live memory/vector-store poisoning + remediation |
| Insecure Inter-Agent Communication | ASI07 | ✅ Full | Trust-boundary attacks, closed-loop vs sanitized |
| Cascading Agent Failures | ASI08 | ✅ Full | Seeded amplification pipeline + ValidationDefense closed-loop |
| Human-Agent Trust Exploitation | ASI09 | ✅ Full | Consent-fatigue approver simulator + compound-action decomposition |
| Rogue Agents | ASI10 | ✅ Full | Three rotating stego exfil channels + CovertChannelDetector |

## External benchmark expansion (Phase E2.9 — see ROADMAP items 55–60)

- [x] InjecAgent harness (1,054 cases deterministic: 0% block / 100% ASR published) (deterministic tool-call grading; second published agentic benchmark)
- [x] tau-bench pass^k (11/11 targets pass^k=1.0 across seeds 42/43/44) consistency metric over per-target series
- [x] R-Judge harness — heuristic floor 47.6%/F1 0.063; **live LLM-judged run published: 89.2% accuracy / F1(unsafe) 0.893 (at the human-agreement ceiling; GPT-4o's published F1 is 74.4%)
- [x] Dual-ASR formal labeling + NIST CAISI alignment citations in RESULTS.md + NIST CAISI methodology-alignment citations in RESULTS.md
- [x] Multi-provider presets (OpenRouter / NVIDIA NIM kinds in provider_from_env) (OpenRouter / NVIDIA NIM) in provider_from_env
- [ ] AgentHarm harness (stretch)

## Remaining before hackathon submission (deadline Aug 31, 5pm PDT)

- [ ] Deploy archon-armor to Cloud Run per [`DEPLOY_GCP.md`](./DEPLOY_GCP.md) (requires GCP credentials)
- [ ] Record ≤4-min demo video (register agent → live battle → Cloud Trace spans → `archon battle --ci` exit 0)
- [ ] Architecture diagram for Devpost
- [ ] Blog post + social post (`#AllThingsAgenticHackathon`)
- [ ] Devpost submission package

## Remaining for enterprise readiness (post-hackathon)

- [x] Full-pipeline benchmark (**RUN Aug 24 — live Gemini full-pipeline ASR 27.2% vs deterministic-tier 66.7%, published in RESULTS.md)
- [x] ClaudeNativeProvider (shipped, commit e37305c)
- [x] Local vLLM attacker provider (shipped, wave 8: VllmProvider preset + docs)
- [x] ASI04/ASI08/ASI09/ASI10 coverage (shipped, waves 1–2: supplychain/cascade/trust/rogue targets)
- [x] HarmBench probe pack (shipped, commit 2841b7f; corpus now 222 across 10 packs (incl. data-exfiltration, ANSI-exfil, package-hallucination))
- [ ] Persistent docs site hosting (mkdocs shipped; GitHub Pages = user-side 2-click)
- [ ] Managed cloud control plane

## OWASP-aligned hardening (Phase E2.6 — see ROADMAP items 23–30)

Derived from the Aug 23 OWASP deep review (Red-Teaming Taxonomy v1.0 + State of Agentic AI v2.01):

- [x] One-click purple runs — `archon purple` fusing battles + compare into a single delta verdict (shipped, wave 5)
- [x] Scheduled fuzzing + autonomous red bots in CI (nightly fuzz workflow + `archon bot`) (shipped, wave 5)
- [x] Kill-switch drill — atomic agent revocation with MTTC measurement (shipped, wave 5: `archon kill-switch`, armor-enforced 503, audit-integrated)
- [x] Beyond-ASI attack patterns — recon/discovery, config-tampering persistence, staged payload delivery (shipped, wave 5: targets/gaps.py)
- [x] Plan-divergence detection — trajectory-level intent-vs-executed monitoring (shipped, wave 5)
- [x] FinBot CTF as external validation target (repo cloned; FinBotTarget live HTTP + FinBotSimTarget now modeling **7 challenge-grounded vectors** — fraud transfer, data exfil, goal hijack, rce-shell-shock foot-in-the-door RCE, scorched-earth poisoned-tool wipe, recon-onboarding policy leak, gradual status flip — each with paired defense + closed-loop tests)
- [x] Nonce store closing the HMAC replay-within-window limitation (shipped, wave 5; auth-boundary tests updated to new behavior)
- [x] Docs site (mkdocs) + security advisory program (shipped, wave 5: mkdocs.yml + docs-site/ + advisory template + security@ contact)

## Submission package & enterprise quick wins (Phase E2.7 — see ROADMAP items 31–44)

Derived from the enterprise A+ ladder analysis (Aug 24) against LANDSCAPE_2026 RFP essentials. All deploy-independent.

- [x] Devpost submission package (shipped, wave 6 — `DEVPOST.md`)
- [x] Demo video script (shipped, wave 6 — `DEMO_SCRIPT.md`)
- [x] Blog/social post draft (shipped, wave 6) (`#AllThingsAgenticHackathon`, bonus points)
- [x] Gemma provider option (shipped, wave 6) (`ARCHON_ATTACK_PROVIDER_KIND=gemma`, bonus points)
- [x] Signed releases (shipped, wave 6) (cosign/Sigstore in release.yml)
- [x] Kill-switch CI drill (shipped, wave 6) (scheduled workflow w/ MTTC assertion)
- [x] Shadow mode (shipped, wave 6) (evaluate-not-enforce would-block logging)
- [x] Full-pipeline benchmark tier (shipped, wave 6; **RUN Aug 24** — live Gemini full-pipeline ASR 27.2% published in RESULTS.md)
- [x] Multi-attempt benchmark series (shipped, wave 6) (CAISI attempt-budget curves)
- [x] Macaroon-style attenuating tokens (shipped, wave 6) (delegation caveat verification)
- [x] Google ADK adapter (shipped, wave 6) (battle target; also mandatory-requirement evidence)
- [x] GitHub Pages docs workflow (shipped, wave 6)
- [x] Multi-tenancy v1 (shipped, wave 6) (tenant-scoped results/registry)
- [x] FinBot CTF adapter (shipped: repo cloned, FinBotTarget + offline sim extended to 7 challenge-grounded vectors; offline benchmark published in RESULTS.md)

## Evidence & hardening sprint (Phase E2.8 / Wave 7 — see ROADMAP items 45–54) — ✅ SHIPPED

- [x] Per-target ground-truth benchmark series (11 targets, aggregate ASR 81.8% from state-diff ground truth, zero LLM calls → RESULTS.md)
- [x] False-positive-rate publication (0/12 benign canaries blocked — 0.0% over-refusal → RESULTS.md)
- [x] Applied-metrics exemplar (UAR 0.75 / PED 4 hops / GUARDEDJOINT quadrants on sandbox banking → RESULTS.md)
- [x] Identity v2: ed25519-signed agent credentials (CredentialStore + Ed25519Verifier drop-in via create_app(identity=...))
- [x] Purple --baseline Policy-CI gate (`archon purple --save-baseline/--baseline`; --ci exits 1 on regression)
- [x] FinBot CTF adapter (repo cloned + FinBotTarget w/ offline sim fallback; live integration tests skip-guarded; sim extended Aug 24 to 7 challenge-grounded vectors from the real YAML definitions)
- [x] Community scaffolding (CONTRIBUTING/CODE_OF_CONDUCT/feature template + tag v1.0.0 exercising release.yml+cosign)
- [x] Architecture diagram (3 Mermaid diagrams in docs-site/architecture-diagram.md; Devpost image slot)
- [x] Docs-site expansion (index + 8 per-target tutorials, verified snippets, ASI mappings)
- [ ] GitHub Pages enablement (user-side 2-click; docs.yml shipped)

## Wave-8 additions (Aug 24 — key-unlocked gap closure)

- [x] LlmBrainAttacker (GOAT-style O-T-S-R loop on provider seam; live-validated vs Gemini: mechanism works, 0/3 @ budget 4 — honest floor documented in RESULTS.md)
- [x] Strict-ASR multi-attempt benchmark (evasion 100% vs strict ASR 18.5% — evasion ≠ compromise, published)
- [x] Local vLLM provider path (VllmProvider + docs + schema-valid example)
- [x] Editor DX wiring (.vscode settings mapping archon.yaml to the JSON schema; VS Code autocomplete)

## Augustus-derived hardening (Phase E2.10 — see ROADMAP items 61–65)

- [x] MCP transport-layer attack target (DNS rebinding / session hijack / off-path attacker, closed-loop verified) (shipped wave 10)
- [x] AI code-review CI workflow (PR review bot) (shipped wave 10)
- [x] Prometheus `/metrics` endpoint on archon-armor (shipped wave 10)
- [x] YAML declarative probe packs (community format) (shipped wave 10)
- [x] Supply-chain CI hygiene (secrets-scan + verify-pins workflows) (shipped wave 10)

## Competitor-mined completion wave (Phase E2.11 — see ROADMAP items 66–89)

24 improvements mined from promptfoo/augustus/agent-scan/garak/PyRIT/NeMo/deepeval/deepteam/ragas source — ALL SHIPPED (waves 11A+11B, Aug 25):
- [x] Tier 1 quick wins: tool-call schema rail (defenses/tool_rail.py), Policy Puppetry + token smuggling converters, SHIFT_DETECTED early-stop wired into crescendo/adaptive, /v1/checks sidecar endpoint, ensemble aggregation, ANSI escape exfil probes (10), hidden-Unicode Cf/Cc scanner w/ U+E0000 tag decoding, agent-loop trace metric, MetricOutputType contract + kappa agreement, package-hallucination probes (10), harm-taxonomy YAML layer (12 defs × 5-level rubrics)
- [x] Tier 2: SARIF 2.1.0 output ⭐ category-first (`archon results --sarif` → GitHub Code Scanning), self-contained HTML report (`archon results --html`), `archon discover` local-config discovery, SKILL.md supply-chain scanning, buff layer (N_probes × N_buffs multiplicative coverage), judge-calibration harness (accuracy/F1/kappa vs human labels), run-history experiment store w/ diffs, toxic-flow capability graph + E002 cross-server shadowing
- [x] Tier 3: coding-agent target suite core-5 (verifier-sabotage / CI-poisoning / procfs-read / egress-bypass / tty-injection), streaming rolling-buffer rails, BEAST deterministic suffix attacker, compliance-card renderer

## Document map

See [`BLUEPRINT_HACKATHON.md`](./BLUEPRINT_HACKATHON.md) §0.
