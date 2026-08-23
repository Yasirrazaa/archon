# Changelog

All notable changes to Archon are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
