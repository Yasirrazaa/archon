# Archon — Current Status

> **Last updated:** August 23, 2026 · **Branch:** `hackathon-v2` · **Suite:** 538 passed / 3 skipped
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
| Probe corpus: 102 probes (encoding-evasion + latent-injection packs added), all 10 OWASP LLM Top-10 categories + 12 benign false-positive canaries | `archon plugins --ci` |
| MCP security: static tool-poisoning scan + live behavioral probing | `archon scan-mcp --url ... --probe-tool NAME` |
| Third-party guardrail validation ("we validate them") | `archon scan --target <guardrail-url>` |
| Pluggable external defenses (NeMo / Model Armor / Promptfoo Guardrails as DefenseLayers) | `ExternalGuardrailLayer` |
| Observability: real OTel SDK → Cloud Trace, PII-scrubbed, immutable audit trail | `ARCHON_OTEL_EXPORTER=otlp` |
| Governance: versioned policies, Postgres registry, append-only audit | `ARCHON_DATABASE_URL` |
| Policy-CI: defense regression gates + fleet gate | `archon scan --gate-baseline` · `archon fleet --ci` |
| Compliance evidence reports (OWASP-mapped HTML/MD) | `archon report` |
| Benchmark harness: AgentDojo v1, all 27 published injection tasks | [`RESULTS.md`](./RESULTS.md) — deterministic-tier ASR 66.7% / block 33.3% |
| Packaging: wheel, non-root Dockerfile, docker-compose, Helm chart | `deploy/helm/archon-armor/` |

## Verified competitive position

Code-verified against 9 competitor repos on Aug 23, 2026 — full analysis in
[`COMPETITIVE_ANALYSIS.md`](./COMPETITIVE_ANALYSIS.md). Headline: promptfoo's adaptive
multi-turn brains run cloud-side; garak is multi-turn now but scanner-only with no defense
evaluation; PyRIT has zero compliance mapping; NeMo defends but cannot self-validate; Snyk
agent-scan never executes attacks and analyzes behind a closed API. Nobody else combines
adaptive offense + shippable defense + adversarial proof.

## Remaining before hackathon submission (deadline Aug 31, 5pm PDT)

- [ ] Deploy archon-armor to Cloud Run per [`DEPLOY_GCP.md`](./DEPLOY_GCP.md) (requires GCP credentials)
- [ ] Record ≤4-min demo video (register agent → live battle → Cloud Trace spans → `archon battle --ci` exit 0)
- [ ] Architecture diagram for Devpost
- [ ] Blog post + social post (`#AllThingsAgenticHackathon`)
- [ ] Devpost submission package

## Document map

See [`BLUEPRINT_HACKATHON.md`](./BLUEPRINT_HACKATHON.md) §0.
