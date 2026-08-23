# Archon — Current Status

> **Last updated:** August 23, 2026 · **Branch:** `hackathon-v2` · **Suite:** 735 passed / 3 skipped
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
| Probe corpus: 120 probes (encoding-evasion + latent-injection packs added), all 10 OWASP LLM Top-10 categories + 12 benign false-positive canaries | `archon plugins --ci` |
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

## Engineering maturity (honest audit, Aug 23)

**Verdict: B+ hackathon, C+ enterprise.** 6,204 src / 7,466 test LOC (1.2:1 ratio), clean
5-seam architecture, zero vendor deps in `archon_core`. What blocks enterprise adoption:

- 🔴 **No CI pipeline** — tests pass locally only; nothing enforces them on PR
- 🟠 No lint/type enforcement (no ruff config, no pre-commit, no coverage gate)
- 🟠 Root install pulls competition deps (`a2a-sdk`, `google-adk`, `google-genai`, `openai`)
- 🟠 Identity: LICENSE says "AgentBeats", v0.1.0, no tags/CHANGELOG/release process
- 🟠 SQLite-first persistence; Postgres path unhardened, no migrations
- 🟠 No threat model of archon-armor itself (no fuzzing, no SECURITY.md/CVE process)

All closure work is scoped as **Phase E0** in [`ROADMAP.md`](./ROADMAP.md). Market context:
[`docs/LANDSCAPE_2026.md`](./docs/LANDSCAPE_2026.md) — enterprises buy operational maturity;
promptfoo wins deals despite weaker agentic attack tech.

## Verified competitive position

Code-verified against 9 competitor repos on Aug 23, 2026 (refreshed post-N3 at 735
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
| Agent Identity & Privilege Abuse | ASI03 | ⚠️ Partial | HMAC identity, but no privilege escalation testing |
| Agentic Supply Chain Compromise | ASI04 | ❌ Gap | Schema manipulation, description deception untested |
| Unexpected Code Execution | ASI05 | ⚠️ Partial | Sandbox targets, but no code-execution battle suite |
| Memory & Context Poisoning | ASI06 | ✅ Full | Live memory/vector-store poisoning + remediation |
| Insecure Inter-Agent Communication | ASI07 | ✅ Full | Trust-boundary attacks, closed-loop vs sanitized |
| Cascading Agent Failures | ASI08 | ❌ Gap | Cascade-recovery behavior untested |
| Human-Agent Trust Exploitation | ASI09 | ❌ Gap | Social engineering attacks untested |
| Rogue Agents | ASI10 | ❌ Gap | Rogue agent detection untested |

## Remaining before hackathon submission (deadline Aug 31, 5pm PDT)

- [ ] Deploy archon-armor to Cloud Run per [`DEPLOY_GCP.md`](./DEPLOY_GCP.md) (requires GCP credentials)
- [ ] Record ≤4-min demo video (register agent → live battle → Cloud Trace spans → `archon battle --ci` exit 0)
- [ ] Architecture diagram for Devpost
- [ ] Blog post + social post (`#AllThingsAgenticHackathon`)
- [ ] Devpost submission package

## Remaining for enterprise readiness (post-hackathon)

- [ ] Full-pipeline benchmark (LLM layers enabled)
- [x] ClaudeNativeProvider (shipped, commit e37305c)
- [ ] Local vLLM attacker provider (zero-code: OpenAI-compat endpoint)
- [ ] ASI04/ASI08/ASI09/ASI10 coverage
- [ ] HarmBench benchmark integration
- [ ] Persistent docs site + live demo
- [ ] Managed cloud control plane

## Document map

See [`BLUEPRINT_HACKATHON.md`](./BLUEPRINT_HACKATHON.md) §0.
