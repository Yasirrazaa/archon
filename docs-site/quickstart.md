# Quickstart

Get any agent behind the archon-armor defense proxy in four steps. These mirror the
[armor walkthrough in README.md](https://github.com/Yasirrazaa/archon#archon-armor-v3-preview--hackathon-v2).

## 1. Register an agent

```bash
uv run archon register --registry ./registry.db --agent-id my-agent --name "My Agent"
```

This prints the agent's HMAC signing secret **once** — store it, it is not shown again.

## 2. Serve the armor proxy

```bash
uv run archon serve --registry ./registry.db \
    --upstream-base-url https://api.upstream.test/v1 --require-signed --port 8080
```

Or via container: `docker compose up armor`. Requests are authenticated with
HMAC signatures (replay-protected, body-bound) — see `SECURITY.md` §2.

## 3. Point your agent at it

```bash
export OPENAI_BASE_URL="http://localhost:8080/v1"   # sign per-request with the agent secret
```

Every request now passes the guard pipeline (normalize → classify → segment → spotlight →
forward → redact output) before reaching the upstream model.

## 4. Scan the agent's policy

```bash
uv run archon scan --registry ./registry.db --agent-id my-agent --ci --min-block-rate 0.5
```

Useful follow-ups:

- `archon scan --checkpoint scan.ckpt` / `--resume scan.ckpt` — long scans survive interruptions
- `archon compare --a baseline.json --b candidate.json --ci` — Policy-CI regression gate
- `archon ui --registry ./registry.db --port 8081` — read-only fleet dashboard at `/ui`
- Community probe packs: see [`contrib/`](https://github.com/Yasirrazaa/archon/tree/main/contrib)

## Prerequisites

Python 3.11+, [uv](https://docs.astral.sh/uv/), and an upstream LLM endpoint. Install from
source with `uv sync` after cloning the repo.
