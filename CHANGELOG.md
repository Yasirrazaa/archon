# Changelog

All notable changes to Archon are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.1] - 2026-08-24

### Added (waves 6–9, Aug 24)

- **Submission package**: DEVPOST.md, DEMO_SCRIPT.md (beat-by-beat 4-min script), BLOG_POST.md draft.
- **Benchmarks**: full published ladder in RESULTS.md — AgentDojo deterministic (66.7% ASR / 0% FPR),
  Tier-3 full-pipeline with live Gemini (27.2%), InjecAgent (1,054 cases), strict multi-attempt ASR
  (evasion 100% vs compromise 18.5%), per-target ground-truth series (81.8%), tau-bench pass^k
  consistency (11/11 = 1.0), R-Judge judge-agreement (heuristic floor + live LLM judge at 89.2%
  accuracy / F1 0.893). All numbers carry attempt-budget/adaptivity/judge methodology blocks.
- **Attackers**: LlmBrainAttacker (GOAT-style O-T-S-R loop), LayerTargetingAttacker,
  CrescendoEscalationAttacker, Gemma provider option, OpenRouter/NVIDIA/vLLM provider presets.
- **Security**: ed25519 identity v2 (CredentialStore + Ed25519Verifier), macaroon-style
  attenuating tokens, shadow mode (evaluate-not-enforce), cosign keyless release signing,
  monthly kill-switch drill workflow with MTTC assertion.
- **Platform**: Google ADK adapter, multi-tenancy v1 (tenant-scoped results), config JSON schema
  + editor autocomplete wiring, GitHub Pages docs workflow, Mermaid architecture diagrams,
  docs-site tutorials ×8, FinBot CTF adapter.

- **ASI05 coverage**: code-execution battle targets — SleeperAgentTarget (dormant planted
  payload detonating on privileged review), SandboxEscapeTarget (allowlist + workspace-path
  escape detection), DestructiveCommandTarget (mass-purge with approval threshold), each with
  a paired defense; OWASP Agentic Top-10 attack coverage now 10/10.
- **FinBot CTF suite**: FinBotSimTarget extended to 7 challenge-grounded vectors (foot-in-the-door
  RCE, two-phase scorched earth, recon policy leak, gradual status flip); offline benchmark
  published — vulnerable ASR 7/7 (100%), defended ASR 0% (all blocked).

## [Unreleased]

### Added (waves 10–11, Aug 25)

- **MCP transport attacks**: DNS-rebinding (TOCTOU), session-hijack, off-path credential-exfil targets with paired defenses.
- **Armor observability**: Prometheus `/metrics` endpoint (per-agent counters + latency histogram).
- **YAML probe packs**: community-contributable packs via `contrib/yaml/` with validation.
- **CI hardening**: AI code-review workflow, secrets-scan, dependency verify-pins.
- **Defense**: fail-closed tool-call schema validation rail (NeMo IORails port); `/v1/checks` standalone sidecar endpoint; streaming output-rail rolling buffers.
- **Attackers**: Policy Puppetry converter, token smuggling (Unicode variation selectors), BEAST beam-search suffixes, buff layer (multiplicative probe fan-out), behavior-shift early-stop (SHIFT_DETECTED) wired into multi-turn attackers.
- **Probes**: corpus 202 → 222 (ANSI escape exfiltration ×10, package hallucination ×10).
- **Targets**: coding-agent suite ×5 (verifier sabotage, automation poisoning, procfs credential read, network egress bypass, terminal-output injection).
- **Reporting**: SARIF 2.1.0 export (GitHub Code Scanning integration — category-first), self-contained HTML battle report, compliance cards (OWASP pass-rate bars + EU-AIA/NIST), judge-calibration harness (Krippendorff α vs R-Judge anchors), run-history store with policy-diff regression views, harm-taxonomy YAML layer (12 defs × 5-level rubrics), metric output contracts, ensemble score aggregation, deterministic agent-loop metric.
- **Discovery & scanning**: `archon discover` local agent-config discovery; SKILL.md supply-chain scanning (injection/downloads/secrets/remote-fetch); toxic-flow capability graph + cross-server tool shadowing (E002); hidden-Unicode scanner with U+E0000 tag decoding.

## [1.0.0] - 2026-08-23

First stable release of the Archon adversarial AI agent security testing platform.

### Added

- **Defense pipeline**: end-to-end 8-layer adversarial defense pipeline with layered
  normalization, threat classification, strategy routing, output guardrails, and
  sequential contract enforcement across execution modes.
- **Armor proxy**: `archon-armor`, an OpenAI-compatible interception proxy that wraps
  any LLM endpoint with live defense layers, streaming support, and observability.
- **Probe packs**: a corpus of 120+ probes organized into encoding, latent, contrib,
  and core packs covering prompt injection, jailbreaks, exfiltration, tool abuse,
  and multi-turn manipulation strategies.
- **AgentDojo benchmark**: integrated AgentDojo harness for standardized agent-security
  benchmarking with reproducible scenario replay and result normalization.
- **Attack targets**: sandbox escape, memory poisoning, multi-agent trust chains,
  MCP tool compromise, supply-chain injection, and rogue-agent attack target suites.
- **Trace-driven generation**: automated probe generation from recorded interaction
  traces, turning observed traffic into new adversarial cases.
- **Severity scoring & compare engine**: normalized severity scoring per probe run plus
  a compare engine for A/B evaluation of defender configurations.
- **Checkpoint / resume**: durable checkpointing and resume for long-running campaigns
  and benchmark sweeps.
- **Web UI**: browser-based console for launching runs, inspecting traces, and
  reviewing scored results.
- **CI pipeline & release**: continuous integration pipeline with full test suite,
  SBOM generation, and reproducible release packaging; competition-only dependencies
  isolated behind the optional `competition` extra for clean distribution.
