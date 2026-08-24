# Running archon-armor against local models (vLLM)

Most guardrail benchmarks are run against hosted APIs, which means every probe
leaves your network. For air-gapped and sovereign deployments — and for
reproducible benchmark numbers — you can point the attack engine at a model you
host yourself with [vLLM](https://docs.vllm.ai/).

Why local models matter:

- **No data egress** — probes never leave the machine; safe for classified or
  customer-confidential evaluations.
- **Air-gapped operation** — no API keys, no outbound firewall exceptions.
- **Reproducibility** — pin an exact model revision and your block rates are
  comparable across runs and teams.

## 1. Serve a model

vLLM exposes an OpenAI-compatible endpoint at `http://localhost:8000/v1`:

```bash
pip install vllm
vllm serve meta-llama/Llama-3.1-8B-Instruct
```

Any model vLLM serves works — the archon attack engine only needs the standard
`POST /v1/chat/completions` contract.

## 2. Wire it into battles

Two ways to point archon's attack engine at the local server.

**Option A — env vars:**

| Env var | Meaning | Example |
| --- | --- | --- |
| `ARCHON_ATTACK_PROVIDER_KIND` | Set to `vllm` to opt into the vLLM path | `vllm` |
| `ARCHON_VLLM_BASE_URL` | OpenAI-compat base URL of your server | `http://localhost:8000/v1` |
| `ARCHON_ATTACK_PROVIDER_MODEL` | Model identifier as served by vLLM | `meta-llama/Llama-3.1-8B-Instruct` |

```python
from archon_core.providers.vllm import vllm_from_env

provider = vllm_from_env()   # reads ARCHON_VLLM_BASE_URL / ARCHON_ATTACK_PROVIDER_MODEL
```

**Option B — direct construction** (useful in tests via transport injection):

```python
from archon_core.providers.vllm import vllm_provider

provider = vllm_provider("meta-llama/Llama-3.1-8B-Instruct")
```

## Caveats

- **Context length**: smaller local models have shorter context windows than
  frontier APIs; long multi-turn battles may truncate.
- **Tool-call support varies**: not every served model implements OpenAI-style
  tool calls; battles that rely on tool use need a capable model.
- **Throughput**: a single GPU serves one model at a time — plan scan parallelism
  accordingly.
