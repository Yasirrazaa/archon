# Tutorials

Hands-on, copy-pasteable walkthroughs of Archon's live attack targets. Each
tutorial models one threat from the
[OWASP Top 10 for Agentic Applications](https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/),
runs a real battle against a vulnerable target, then flips the paired defense
on and watches the attack fail — the closed loop in miniature.

## Prerequisites

Python 3.11+, [uv](https://docs.astral.sh/uv/), cloned repo, `uv sync`.
All commands run from the repo root; every snippet is deterministic and needs
**no LLM API key** (targets are instrumented simulators with ground-truth
verdicts).

## The tutorials

| Tutorial | Threat modeled | OWASP ASI | Target module |
|---|---|---|---|
| [Your first memory-poisoning battle](first-memory-poisoning-battle.md) | Poison planted in a live vector store hijacks later benign queries | ASI06 Memory & Context Poisoning | `archon_core.targets.memory` |
| [Your first tool-sandbox battle](first-tool-sandbox-battle.md) | Injected directives drive a real tool-executing agent to drain an account | ASI02 Tool Misuse | `archon_core.targets.sandbox` |
| [Multi-agent trust boundary](multi-agent-trust-boundary.md) | Compromised worker smuggles directives across agent-to-agent hops | ASI07 Insecure Inter-Agent Communication | `archon_core.targets.multiagent` |
| [MCP rug-pull](mcp-rug-pull.md) | Tool-description hijack redirects routing to a poisoned tool | ASI02 Tool Misuse / MCP03 | `archon_core.targets.mcp_battles` |
| [Supply-chain pinning](supply-chain-pinning.md) | Approved tool server silently mutates after N clean calls (CVE-2025-54136 class) | ASI04 Agentic Supply Chain | `archon_core.targets.supplychain` |
| [Approval fatigue & trust](approval-fatigue-trust.md) | Action decomposition defeats a tired human approval layer | ASI09 Human-Agent Trust Exploitation | `archon_core.targets.trust` |
| [Rogue stego channels](rogue-stego-channels.md) | Insider agent exfiltrates secrets via acrostic / zero-width / base64 channels | ASI10 Rogue Agents | `archon_core.targets.rogue` |
| [Beyond-ASI gap patterns](beyond-asi-gap-patterns.md) | Recon disclosure, config tampering, staged payloads — patterns the Top 10 misses | OWASP gap appendix | `archon_core.targets.gaps` |

## Why closed-loop?

Chat-target benchmarks score "did the response contain a marker". These targets
score **state**: was money actually moved, was the store actually poisoned, did
the secret actually ride out inside legitimate-looking output? That ground truth
is what makes the red/blue loop honest — see
[architecture-diagrams](../architecture-diagram.md) for how battles, the
defense pipeline, and Policy-CI fit together.

Start with [your first memory-poisoning battle](first-memory-poisoning-battle.md).
