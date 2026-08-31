# SUBMISSION.md — Devpost text (TRUTHFUL, verified against repo Aug 31, 2026)

Category: **Fortified Enterprise Fleet**
Repo: **https://github.com/Yasirrazaa/arcon** (branch `hackathon-v2`)
Deployment: **deployed on Google Cloud Run — full build/deploy/trace sequence
shown in the demo video** (per Devpost rules the service need not stay live;
redeploy any time with `bash deploy/gcp/deploy.sh`). Dashboard preview and the
Cloud Run/Cloud Trace proof are at the timestamps below.

---

## What Archon Does

Archon is the only open-source platform where an adaptive attacker and a
measurable defense fight in the same loop, with every verdict exported as
OWASP-mapped audit evidence. It is MIT-licensed, self-hostable, and
vendor-neutral.

## Problem

Enterprises deploying AI agents cannot *prove* their defenses work. Commercial
filters grade their own homework; open-source scanners attack but don't ship a
defense; and nobody emits adversarially-validated compliance evidence.

## Solution — all seven Fortified Fleet requirements, shipped and tested

- **Agent Registry**: PostgresRegistry (+SQLite/In-Memory), versioned policies,
  append-only audit trail, `archon register` CLI printing signing secrets.
  (Demo runs the SQLite registry baked into the Cloud Run image.)
- **Agent Runtime**: `BattleManager` async submit/poll, checkpoint/resume for
  crash-safe long battles, multi-turn `BranchingAttacker` with deterministic
  scoring (no LLM judge on the verdict path).
- **Memory Bank**: durable results store (`archon results`), battle history,
  deterministic share tokens, baseline store for regression gates.
- **Agent Identity**: HMAC signed identity, kill-switch revocation
  (`archon kill-switch`), attenuating caveats, ed25519 approvals.
- **Agent Gateway**: `archon-armor` FastAPI OpenAI-compatible proxy at
  `/v1/chat/completions` — drop-in via one `OPENAI_BASE_URL` env var.
- **Model Armor (defense)**: 8-layer pipeline (normalization → threat
  classification → trust segmentation → spotlighting → execution mode →
  constitution → exchange classification → output guardrails); the deterministic
  tier costs zero LLM calls, full pipeline stays within a 4-call budget.
- **Agent Observability**: real OpenTelemetry SDK → Cloud Trace, per-layer
  spans, PII-scrubbed, JSONL fallback, immutable audit.

## Technologies Used

- **Gemini API** (`gemini-2.0-flash-lite-001`, `gemini-2.5-flash`): attack brain
  + LLM-backed defense layers, via the OpenAI-compat endpoint.
- **Gemma** (`gemma-3-27b-it`): first-class provider via the `LLMProvider` seam.
- **Cloud Run**: containerized archon-armor (non-root, /healthz, /metrics).
- **Cloud Trace**: OTLP span export with GCP metadata-server auth.
- **SQLite/Postgres registry**, FastAPI, Pydantic, pytest (2,400+ tests), Helm
  chart, Docker/docker-compose.

## Other Data Sources

- OWASP LLM Top-10 (2025) — **222 probes** across all 10 categories.
- NIST CAISI-aligned methodology discipline (declared attempt budgets/judges).
- AgentDojo (27 injection tasks) and InjecAgent-style tool-injection threat
  model; R-Judge (571 human-labeled records) for judge-agreement calibration.

## Key Findings (measured on this codebase, see RESULTS.md)

1. **Evasion ≠ compromise (dual ASR)**: 100% of tasks evade the rule tier within
   2 attempts, yet strict ASR (actual model compliance) is **18.5%** — publishing
   evasion alone overstates attacker success by >5× (WASP-style ASR-intermediate
   vs ASR-end-to-end).
2. **Model choice dominates**: strict ASR swings **18.5% → 74.07%** on model
   selection alone — a single ASR number without naming the target model is noise.
3. **Defense-in-depth compounds**: the zero-cost deterministic tier cuts
   full-pipeline ASR 27.2% → 12.35%.
4. **Judge reliability**: keyword heuristics score F1 ≈ 0.06; our LLM judge hits
   **0.893 F1** on R-Judge (89.2%) — at the human-agreement ceiling.
5. **False positives matter as much as recall** — the corpus ships benign
   controls and coverage matrices report blocked *and* passed.

## What Makes Archon Unique

- **Closed loop**: attack → shield → re-attack (`archon purple`) → evidence
  export (JSON/SARIF/HTML). Attack tools and defense tools exist separately
  everywhere else; the loop is the moat.
- **Policy-CI**: `--ci` exit codes on scan/battle/fleet gate defense regressions
  in CI/CD — invented here, still rare.
- **Five extension seams** (packs, layers, providers, targets, reporters) with
  a community pack loader (`archon plugins`, `load_pack_file`).
- **Enterprise hardening shipped**: Helm chart (non-root, probes, /data),
  Postgres registry, kill-switch drills, fleet dashboard.

## Learnings

1. The measurement loop is the moat — offense alone commoditizes.
2. Determinism first: rule-based layers buy 80% of the defense at zero cost.
3. Honest evidence (what blocked, why, at which layer) is the enterprise unlock.

*This project was created for the purposes of entering the All Things Agentic
Hackathon.*
