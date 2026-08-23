# archon-security (npm wrapper)

Node-friendly entry point to the **Archon** security CLI. Archon itself is a
Python package — this wrapper shells out through [uv](https://docs.astral.sh/uv/)
(preferred) or [pipx](https://pipx.pypa.io/) so you don't manage a venv.

## Prerequisites

Install **one** of:

```bash
curl -LsSf https://astral.sh/uv/install.sh | sh   # uv (recommended)
# or
pipx ensurepath                                    # pipx
```

## Usage

```bash
npx archon-security plugins --ci
npx archon-security register --registry ./registry.db --agent-id my-agent --name "My Agent"
npx archon-security scan --registry ./registry.db --agent-id my-agent --ci
```

## Why a wrapper?

Archon's defense pipeline, battle engine, and observability bridge are Python
(see the repo root). The npm package exists so teams with Node-based CI can
adopt the same CLI without switching toolchains — the shim simply forwards all
arguments to the real `archon` binary.
