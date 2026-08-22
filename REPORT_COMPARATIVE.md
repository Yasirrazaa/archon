# ARCHON — Comparative Security Report
**Date:** August 22, 2026 · **Branch:** `hackathon-v2` · **Suite:** 505 passed / 3 skipped

---

## 0. Executive summary

Archon is the **only open platform that combines three things no single incumbent
ships together**: (1) multi-turn, stateful, deterministic-scored adaptive attacks,
(2) a production-grade defense pipeline shipped as a drop-in, measurable runtime
(the armor proxy), and (3) **red-vs-blue validation** — attack *and* defense in one
loop, with per-layer evidence exported as audit/OTel/compliance artifacts.

The market has moved since this project began (Promptfoo → OpenAI, five product
lines; Snyk acquired Invariant Labs; Garak/NVIDIA and PyRIT/microsoft keep shipping).
The attack side is commoditizing. The **durable, defensible position** is
"measurement" — nobody else adversarially validates their own or third-party
defenses with per-layer evidence and a policy gate. That is our wedge.

---

## 1. What Archon is today (verified by test suite + live CLI)

| Capability | Implementation | Notes |
|---|---|---|
| Defense pipeline | 8 layers (Normalization → ThreatClassification → Segmentation → Spotlighting → ExecutionMode → OutputGuardrails → ExternalGuardrail + exchange/backtranslation logic) wrapping the proven AgentBeats defender | layer-0 deterministic; LLM-budget-aware; fail-closed |
| Probe corpus | 53 probes, all 10 OWASP LLM Top-10 categories; LLM01 family deterministically blocked by reference pipeline | `owasp_llm_10` (49) + `core` (4); per-category coverage matrix in every battle summary |
| Adaptive attacker | `BranchingAttacker` — Hydra-style fan-out/pivot/prune; **deterministic** refusal-vs-leak scoring (no LLM judge); provider-failure degradation | First-class in battle API + `archon battle --ci` |
| Runtime product | `archon-armor` — FastAPI OpenAI-compatible proxy, HMAC signed identity, per-agent policy, rate limiting, output redaction | Drop-in: change `OPENAI_BASE_URL` |
| Identity & governance | HMAC replay-protection, per-agent secrets, immutable append-only audit trail, versioned policies | Enterprise-grade |
| Observability | Real OpenTelemetry SDK bridge (`ARCHON_OTEL_EXPORTER=otlp → Cloud Trace`), PII-scrubbed, JSONL fallback, immutable audit | Unique density among competitors |
| MCP security | Static tool-poisoning scan + **live behavioral probing** (`scan-mcp --url --probe-tool`) | Snyk is static-only, closed-source |
| Scanning remote guards | `archon scan --target` any OpenAI-compatible guardrail, with policy gates | "We validate them" |
| Guardrail-as-layer | `ExternalGuardrailLayer` (NeMo/Model Armor/front proxies become pluggable vs attack surface) | |
| CI/CD tooling | Major commands have `--ci` exit codes; JSON; `archon.yaml` config-as-code | |
| Policy-CI baselines | `BaselineStore` + regression gate; `archon scan --update/gate-baseline` | Category-defining |
| Fleet overview | `archon fleet --registry --baselines --min-block-rate --ci` | Managed-cloud seed |
| Packaging | Wheel, Dockerfile (non-root), docker-compose, **Helm chart** | Enterprise-ready |
| Registries | In-memory, sqlite, **Postgres**, versioned | Enterprise durability |
| Compliance evidence | OWASP-mapped HTML/Markdown evidence reports | CISO-facing |

System health: **505 passed / 3 skipped** (skips: live-Postgres integration behind
`ARCHON_TEST_DATABASE_URL`; `helm lint`/`template` behind helm binary).

---

## 3. Competitor scorecard (verified Aug 22, 2026)

Legend: ● mature/best-in-class · ◐ partial/new · ○ absent

| Dimension | **Archon** | Promptfoo | Garak | PyRIT | NeMo Guardrails | Snyk Agent Scan | Model Armor |
|---|---|---|---|---|---|---|---|
| Multi-turn adaptive attacks | ● | ◐ | ◐ (GOAT new) | ● | — | — | — |
| Attack corpus breadth | ◐ 53 | ● 157+ | ● 100+ | ◐ | — | ◐ | — |
| Defense evaluation (red/blue) | ● | — | — | — | — | — | — |
| Runtime guardrail product | ● proxy | ◐ guardrails | — | — | ● | — | ● |
| Layer per-request telemetry | ● | ◐ | — | — | ◐ | — | ◐ |
| Identity/registry/policy | ● | ◐ | — | — | ◐ | — | ● |
| CI/CD + config-as-code | ● | ● | ◐ | — | — | ● | — |
| OTel observability | ● | ◐ | — | — | — | — | ◐ |
| MCP security (live) | ● | ◐ | — | — | ◐ | ○ static | — |
| Open self-hosted | ● MIT | ◐ | ● Apache-2.0 | ● MIT | ● Apache-2.0 | ○ | ○ |
| Compliance evidence | ● | — | — | — | — | — | — |

**Reading the table:** Promptfoo and Garak/PyRIT attack well but cannot measure a
defense. NeMo/Model Armor defend but cannot prove it. Snyk static-scans, closed.
AgentDojo is a benchmark, not a tool. Nothing else issues per-layer defense
## 4. Honest gaps (where competitors still lead)

These are the rows we must own to be the best at anything, not just the best "gap".

1. **Probe/plugin corpus** — 53 probes is respectable but Promptfoo (157+) and
   Garak (100+) are ahead. Our loader now lets the community scale this.
2. **Model/harness breadth** — Garak's generator/transport matrix and Promptfoo's
   provider list are deeper than our two providers. Attacker-side LLM diversity
   matters for benchmark credibility.
3. **Live ecosystem (docs, real configs, first-run DX)** — Garak/Promptfoo ship
   batteries-included examples and VS Code tooling; we have docs + Docker + Helm
   but no full real-cloud live demo yet (that is the hackathon-pending item).
4. **Canned benchmark numbers** — AgentDojo/HarmBench-style ASR numbers remain
   unpublished. Publishing ASR on AgentDojo against published baselines is the
   fastest researcher/credibility grab.
5. **Community/team** — incumbents have thousands of contributors; Archon is
   largely solo. The plugin seams + MIT license help attract, but mindshare
   takes time.

---

## 5. Market dynamics (verified)

- Promptfoo is now OpenAI-owned and expanded to a 5-product security suite
  (Red Teaming, Guardrails, Model Security, MCP Proxy, Code Scanning), shipping
  weekly. This validates the category (offense + defense are one problem) and is
  their neutrality weakness ("vendor grades its own homework").
- Snyk Agent Scan absorbed the Invariant MCP-scan line; v0.6 is risk-scored but
  closed to contributions and depends on Snyk's hosted API. The live-behavior MCP
  lane is open.
- Garak stays a scanner (not a platform); PyRIT added a GUI; NeMo Guardrails added
  telemetry-style audit — none shrink the red/blue gap.
- Cloud/security incumbents (Datadog, CrowdStrike, Palo Alto) will likely enter or
  acquire their way in within 6–12 months. **Speed is the strategy.**

---

## 6. Recommendation / priority order (next 90 days)

**Hackathon (≤ Aug 31):** deploy Cloud Run via `DEPLOY_GCP.md`, record the 4-min
demo (register → live battle → blocked trace in Cloud Trace → `archon battle --ci`),
blog + `#AllThingsAgenticHackathon` post.

**Then (in this order):**
1. **Publish a live demo + docs** — one Docker + Postgres + Helm template, one
   YouTube walkthrough. Makes it usable, credible, enterprise-pilot-ready.
2. **AgentDojo / benchmark runner** — clone the benchmark, run Archon's attacker
   against published defense baselines, publish ASR numbers + a report.
3. **Probe corpus 100+** — add adversarial benchmark suites (HarmBench) as packs;
   port top Garak/Promptfoo families via the loader.
4. **Attacker diversity** — providers beyond OpenAI-compat (local vLLM, Claude,
   Gemini native) via the `LLMProvider` seam, benchmark-driven tuning.
5. **Ecosystem** — `contrib/` gallery, CI matrix for community pulls, plugin
   marketplace directory in README.

Each is small, tested, and compounds: every one either adds users, adds proof, or
closes a gap the incumbents still hold.

---

*Sources: live vendor docs/repos verified Aug 22, 2026; project internals verified by
the 505-test suite and `archon plugins` output on `hackathon-v2`.*
evidence inside a red-team loop.