# Devpost Submission Package — Archon

> Ready to paste into the Devpost submission form. All Things Agentic Hackathon · Track: **Fortified Enterprise Fleet**.

---

## Project name

**Archon** — closed-loop agent security: red team and blue team in one system.

## Tagline (short pitch)

Archon attacks your AI agent, deploys its shield, then re-attacks to *prove* the shield works — with OWASP/NIST/EU-AI-Act-mapped evidence at every layer.

## What it does

Most agent-security tools are half a loop. Scanners (garak, PyRIT) attack but can't defend. Guardrails (NeMo) defend but can't prove they work. Cloud red-team platforms hide their attack brains behind an API.

**Archon is the only open platform where red team and blue team are the same system:**

1. **Attack** — a 222-probe corpus across OWASP LLM Top 10, OWASP Agentic Top 10 (ASI01–10), HarmBench behavioral domains, jailbreak personas, encoding evasion, latent injection, and data exfiltration; plus live attack targets that execute real tool calls in instrumented sandboxes, poison real memory stores, cross real multi-agent trust boundaries, rug-pull simulated MCP servers, and exploit approval fatigue.
2. **Defend** — archon-armor, a drop-in OpenAI-compatible proxy (point `OPENAI_BASE_URL` at it), enforcing an 8-layer defense pipeline: normalization → threat classification → segmentation → spotlighting → execution-mode control → output guardrails, with HMAC workload identity, nonce-based replay protection, rate limiting, per-agent policy, and an atomic kill switch with measured MTTC.
3. **Prove** — re-run the same attacks against the shielded agent and emit a delta verdict (`archon purple --ci`). Every finding carries evidence-derived severity vectors, tamper-evident hashes, chain-of-custody, and compliance-control mapping (EU AI Act Art. 9/15, NIST MEASURE-2/MANAGE-2, ISO 42001 A.6.1.6).

Fleet operators get `archon fleet --ci` as a merge-blocking policy gate, a web dashboard, checkpoint/resume for long campaigns, trace-driven attack generation from OTel spans, plan-divergence detection, shadow mode (measure would-block rates before enforcing), and scheduled fuzzing + autonomous red bots in CI.

## How we built it

- **Python + uv workspace**, five clean extension seams (AttackStrategy / DefenseLayer / LLMProvider / TargetAdapter / Registry), MIT-licensed v1.0.0.
- **Gemini API** powers the adaptive attack engine via its OpenAI-compatible endpoint (`ARCHON_ATTACK_PROVIDER_KIND=openai|gemma|anthropic`); Claude native provider included.
- **Google Agent Framework**: Google ADK adapter wraps ADK agents as battle targets; Gemini OpenAI-compat integration throughout.
- **GCP**: deployed on **Cloud Run** (GCS-backed durable state), with **Cloud Trace** via OTel — every request emits a span tree showing each defense layer's verdict (`service.name=archon-armor`). See DEPLOY_GCP.md for the verified spin-up path.
- **Engineering discipline**: 1,868 tests (TDD, ~1.2:1 test:code ratio), CI matrix on Python 3.11–3.13 with ≥85% coverage gate, ruff, nightly fuzzing, SBOM + cosign-signed releases, Postgres integration job, schema migrations, SECURITY.md threat model with honest limitations.

## Published results (all attempt-budget-disclosed — see RESULTS.md)

| Benchmark | Result |
|---|---|
| AgentDojo v1 (deterministic tier, 81 attacks) | ASR 66.7% / block 33.3% · false-positive rate 0.0% (0/12 benign canaries) |
| AgentDojo Tier-3 (full pipeline + live Gemini) | **ASR 27.2%** — defense-in-depth measured end-to-end |
| InjecAgent (1,054 tool-injection cases) | deterministic tier 0% block / 100% ASR → why LLM layers exist |
| Strict multi-attempt ASR (budget 5) | evasion 100% vs **strict compromise 18.5%** — "evasion ≠ compromise" |
| Per-target ground-truth series (11 live targets) | ASR 81.8%, verified by environment state diffs |
| tau-bench pass^k consistency (3 seeds) | 11/11 targets pass^k = 1.0 |
| R-Judge judge agreement (571 records) | **89.2% accuracy / F1 0.893** — at the human ceiling (89.07%); GPT-4o's published F1 is 74.4% |
| FinBot CTF challenge suite (7 vectors, offline sim) | vulnerable ASR 100% (7/7 flags) vs defended 0% — modeled from the official OWASP-referenced challenge YAMLs |

No competitor publishes attempt budgets, judge methods, or dual-ASR breakdowns. We publish all of them.

## Why it's different (judging: Innovation & Operational Utility)

Verified against cloned source of garak, promptfoo (OpenAI), Microsoft PyRIT, NeMo Guardrails, AgentDojo, DeepTeam, Snyk agent-scan:

| Capability | Archon | Best competitor |
|---|---|---|
| Live tool-execution attacks w/ env-state ground truth | ✅ | AgentDojo (static templates only) |
| Real memory/vector-store poisoning | ✅ | nobody (all simulate) |
| ASI07 multi-agent trust-boundary attacks | ✅ | promptfoo maps only |
| Supply-chain rug-pull simulation (ASI04) | ✅ | static scans only |
| Closed-loop purple verification (attack→shield→re-attack) | ✅ | nobody |
| Self-hosted enforcement proxy | ✅ | NeMo (no offense/compliance) |
| Evidence-derived severity + compliance packs | ✅ | DeepTeam (hardcoded impact) |
| Trace-driven attack generation | ✅ | evaluate-only elsewhere |

Full scorecard: COMPETITIVE_ANALYSIS.md §7.1.

## Architecture description

See ARCHITECTURE section in README + docs-site/architecture.md. Core-first packages: `archon_core` (attacks, defenses, targets, observability, reporting, security), `archon_armor` (proxy server, battles, compare, purple, UI), `archon_cli`, `archon_benchmarks`.

## Run it

```bash
uv sync
uv run archon register --help   # register an agent
uv run archon serve             # armor proxy
uv run archon scan --target ... # remote guardrail scan
uv run archon purple --registry registry.db --agent-a a1 --agent-b a2 --ci
```

Full GCP deployment: DEPLOY_GCP.md (Cloud Run + Cloud Trace proof included in demo video).

## Team

Built for the All Things Agentic Hackathon by [@Yasirrazaa](https://github.com/Yasirrazaa).

---

### Checklist before submitting
- [ ] Paste sections into Devpost form fields
- [ ] Link demo video (YouTube/Drive)
- [ ] Link repo: https://github.com/Yasirrazaa/archon (hackathon-v2 branch merged or noted)
- [ ] Add architecture diagram image (see DEMO_SCRIPT.md shot list)
- [ ] Check "Fortified Enterprise Fleet" track + required-tech checkboxes (Gemini API ✓, Google ADK ✓, Cloud Run ✓)
