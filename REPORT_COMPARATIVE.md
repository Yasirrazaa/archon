# ARCHON — Comparative Security Report
**Date:** August 23, 2026 · **Branch:** `hackathon-v2` · **Suite:** 884 passed / 3 skipped

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
| Probe corpus | 120 probes: all 10 OWASP LLM Top-10 categories + 12 benign false-positive canaries (test-enforced unblocked) + Garak-lineage `encoding_evasion` (15) and `latent_injection` (15) packs + community gallery (`contrib/`: finance/healthcare/devops ×18) — every encoded/latent probe deterministically decoded and blocked by the reference pipeline (test-enforced) | `owasp_llm_10` (56) + `encoding_evasion` (15) + `latent_injection` (15) + `harmless_helpfulness` (12) + `core` (4) + contrib (18); per-category coverage matrix in every battle summary |
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
| Benchmarks | AgentDojo v1 harness: all 27 published injection tasks × 3 wrappers = 81 attacks; published ASR/block numbers | [`RESULTS.md`](./RESULTS.md) |
| Severity scoring | Evidence-derived CVSS-style 0–10 scores (threat class × execution-mode exposure × evasion delivery), vector strings, bands — rendered in evidence reports | DeepTeam's impact is hardcoded MEDIUM |
| Live tool-execution battles | Sandbox targets with real tool calls + ground-truth env-diff verification (`attack_success`); closed-loop defended/undefended proof | AgentDojo has envs but static templates; DeepTeam/promptfoo simulate via text callbacks |
| Trace-driven attack generation | Mines span streams (layers that never fired, live tools, leaked error internals) into targeted evasion/injection/exploit attacks | promptfoo/DeepEval only *evaluate* from traces; nobody *attacks* from them |
| ASI07 multi-agent trust-boundary attacks | Swarm target where the coordinator sanitizes direct input but trusts worker output — smuggled directives cross the boundary and leak secrets; closed-loop vs `sanitize_boundary` variant | promptfoo maps ASI07, DeepTeam scores it as a metric; nobody executes the attack |
| Comparison engine (`archon compare`) | A-vs-B diff of battle reports: block-rate delta, per-category coverage deltas, newly blocked/unblocked probes, severity movement, `improved/regressed/equal` verdict, `--ci` gate | Baselines elsewhere are store-only; no competitor ships policy-version diffing with a CI verdict |
| Checkpoint/resume battles | Verdicts persisted after every probe (atomic writes); interrupted campaigns resume skipping completed probes (`archon scan --checkpoint/--resume`) | Long adaptive campaigns elsewhere lose all state on crash |
| Web UI fleet dashboard | Zero-dependency dark-theme UI at `/ui`: fleet agents + policies (secrets never serialized) + recent battles, 10s auto-refresh (`archon ui`) | garak/promptfoo/PyRIT reports are post-hoc files; NeMo has no fleet view; Snyk's is cloud-side |
| Contrib pack gallery | Curated finance/healthcare/devops probe packs (18 namespaced probes), README-indexed, auto-discovered via `ARCHON_CONTRIB_DIR` | garak plugins are in-tree only; promptfoo verticals are remote-generation cloud plugins |
| Distribution | Homebrew formula + npm wrapper (`npx archon-security`) around the uv-installed MIT CLI | PyRIT/garak are pip-only; DeepTeam requires a Confident cloud account for full flow |
| Contrib pack gallery | Curated finance/healthcare/devops probe packs (18 namespaced probes), README-indexed, auto-discovered via `ARCHON_CONTRIB_DIR` | garak plugins are in-tree only; promptfoo verticals are remote-generation cloud plugins |
| Distribution breadth | Homebrew formula + npm wrapper (`npx archon-security`) around the uv-installed MIT CLI | PyRIT/garak are pip-only; DeepTeam requires Confident cloud account for full flow |
| Live memory/vector-store poisoning | Plants real poison entries in a live store; benign user queries retrieve them and the RAG target obeys; remediation scrubbing verified closed-loop | promptfoo's `agentic:memory-poisoning` is a simulated two-step scenario; nobody else touches real stores |

System health: **884 passed / 3 skipped** (skips: live-Postgres integration behind
`ARCHON_TEST_DATABASE_URL`; `helm lint`/`template` behind helm binary).

---

## 3. Competitor scorecard (verified Aug 22, refreshed Aug 23 post-N3 — 884 tests)

Legend: ● mature/best-in-class · ◐ partial/new · ○ absent

| Dimension | **Archon** | Promptfoo | Garak | PyRIT | NeMo Guardrails | Snyk Agent Scan | Model Armor |
|---|---|---|---|---|---|---|---|
| Multi-turn adaptive attacks | ● | ◐ (brains cloud-side) | ● (GOAT/TAP/Agent Breaker) | ● | — | — | — |
| Attack corpus breadth | ● 120 probes + AgentDojo harness | ● ~150 plugins | ● 195 probes | ● 94 templates + 59 datasets | — | ◐ | — |
| Defense evaluation (red/blue) | ● | — | — | — | — | — | — |
| Runtime guardrail product | ● proxy | ◐ guardrails (cloud client) | — | — | ● | ◐ hooks (cloud-enforced) | ● |
| Layer per-request telemetry | ● | ◐ | — | — | ◐ | — | ◐ |
| Identity/registry/policy | ● | ◐ | — | — | ◐ | — | ● |
| CI/CD + config-as-code | ● | ● | ◐ | ◐ (`pyrit_scan`) | — | ● | — |
| OTel observability | ● | ◐ | — | — | ◐ | — | ◐ |
| MCP security (live) | ● | ◐ | — | — | ◐ | ○ static | — |
| Published benchmark numbers | ● AgentDojo v1 | ◐ | ◐ | ◐ | — | — | — |
| Open self-hosted | ● MIT | ◐ | ● Apache-2.0 | ● MIT | ● Apache-2.0 | ○ | ○ |
| Compliance evidence | ● | ◐ mapping only | ◐ tags only | — | — | — | — |

### 3.1 Agentic attack surface (post-N3 — the rows that decide the category)

| Dimension | **Archon** | Promptfoo | Garak | PyRIT | DeepTeam | AgentDojo | NeMo |
|---|---|---|---|---|---|---|---|
| Live tool-execution attacks w/ env-state ground truth | ● sandbox targets, `attack_success` from state diff | ◐ simulated via text callbacks | ◐ chats about tools, no sandbox | — | ◐ text callbacks only | ● envs but static templates | — |
| Live memory/vector-store poisoning | ● real store manipulation + remediation loop | ◐ simulated two-step scenario | — | — | ◐ metric-only | — | — |
| ASI07 multi-agent trust-boundary attacks | ● smuggled directives cross worker→coordinator boundary; closed-loop vs sanitized variant | ◐ maps ASI07, doesn't attack it | — | — | ◐ metric-only | — | — |
| Evidence-derived severity scoring | ● CVSS-style, every component derived from battle evidence | ◐ severity tiers | ◐ taxonomy tags | — | ◐ impact hardcoded MEDIUM | — | — |
| Trace-driven attack generation | ● mines spans into targeted evasion/tool/error exploits | ◐ trace-driven *evaluation* only | — | — | ◐ TraceScanner evaluates only | — | — |
| Policy-version comparison engine | ● `archon compare` with regression verdict + CI gate | — | — | — | — | — | — |
| Fleet dashboard UI | ● zero-dependency `/ui`, agents+policies+battles | ● web viewer (local evals) | ◐ HTML report file | ◐ CoPyRIT GUI | — | — | — |

**Reading the tables:** Promptfoo and Garak/PyRIT attack well but cannot measure a
defense. NeMo/Model Armor defend but cannot prove it. Snyk static-scans, closed.
AgentDojo is a benchmark, not a tool. On the §3.1 agentic rows — the dimensions
that define agent security in 2026 — Archon holds ● on all seven while no
competitor holds more than one ◐. As of Aug 23 Archon is also the only one of
these projects publishing reproducible AgentDojo numbers from its own harness.

## 4. Honest gaps (where competitors still lead)

These are the rows we must own to be the best at anything, not just the best "gap".

1. **Probe/plugin corpus** — 102 probes is respectable but Promptfoo (~150 plugins) and
   Garak (195 probes) are ahead. Our loader now lets the community scale this; the
   AgentDojo harness adds benchmark credibility that raw plugin count can't.
2. **Model/harness breadth** — Garak's generator/transport matrix and Promptfoo's
   provider list are deeper than our OpenAI-compat + Gemini providers. Attacker-side LLM
   diversity (Claude native, local vLLM) matters for benchmark credibility.
3. **Live ecosystem (docs, real configs, first-run DX)** — Garak/Promptfoo ship
   batteries-included examples and VS Code tooling; we have docs + Docker + Helm
   but no full real-cloud live demo yet (that is the hackathon-pending item).
4. ~~Canned benchmark numbers~~ — ✅ **CLOSED (Aug 23):** AgentDojo v1 numbers published in [`RESULTS.md`](./RESULTS.md) with a baseline comparison. HarmBench-style breadth remains future work.
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
2. ~~AgentDojo / benchmark runner~~ — ✅ **DONE (Aug 23):** harness shipped, numbers published in [`RESULTS.md`](./RESULTS.md). Next: run with LLM layers enabled for the full-pipeline ASR.
3. **Probe corpus 100+** — add adversarial benchmark suites (HarmBench) as packs;
   port top Garak/Promptfoo families via the loader.
4. **Attacker diversity** — providers beyond OpenAI-compat (local vLLM, Claude
   native) via the `LLMProvider` seam, benchmark-driven tuning.
5. **Ecosystem** — `contrib/` gallery, CI matrix for community pulls, plugin
   marketplace directory in README.

Each is small, tested, and compounds: every one either adds users, adds proof, or
closes a gap the incumbents still hold.

---

*Sources: live vendor docs/repos verified Aug 22, 2026; competitor source code
(cloned repos) verified Aug 23, 2026; project internals verified by the 884-test
suite and `archon plugins` output on `hackathon-v2`.*