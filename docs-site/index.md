# Archon

**Adversarial AI agent security testing framework.**

Archon is an agent-security platform built for the Lambda × Berkeley RDI AgentBeats
Security Arena: attacker and defender agents battle across adversarial scenarios, and the
defender stack ships as a deployable OpenAI-compatible proxy (`archon-armor`) that any
agent can adopt by changing one environment variable.

Competition result: **13th overall, 6th Defend (85.1% defense win rate)** on the private
leaderboard.

## Where to go next

| Page | What it covers |
|---|---|
| [Quickstart](quickstart.md) | Register an agent, run the armor proxy, scan its policy |
| [Architecture](architecture.md) | Core-first package layout and extension seams |
| [Security](security.md) | Threat model, known limitations, vulnerability reporting |
| [Benchmarks](benchmarks.md) | Published AgentDojo v1 numbers, honestly scoped |

## Canonical docs

This site is a thin curated index. The authoritative sources live in the repo root:

- [`README.md`](https://github.com/Yasirrazaa/archon/blob/main/README.md) — overview, armor walkthrough, distribution channels
- [`STATUS.md`](https://github.com/Yasirrazaa/archon/blob/main/STATUS.md) — current-state snapshot (start here for what's shipped)
- [`BLUEPRINT_HACKATHON.md`](https://github.com/Yasirrazaa/archon/blob/main/BLUEPRINT_HACKATHON.md) — v3 architecture rationale and roadmap
- [`SECURITY.md`](https://github.com/Yasirrazaa/archon/blob/main/SECURITY.md) — threat model and disclosure process
- [`RESULTS.md`](https://github.com/Yasirrazaa/archon/blob/main/RESULTS.md) — published benchmark numbers

Status (Aug 2026): active development on branch `hackathon-v2` toward Archon v3 — a
production-ready core library, deployable defense proxy, and CLI.
