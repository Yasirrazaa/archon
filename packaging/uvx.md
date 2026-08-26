# Running archon via uvx

The CLI ships as a wheel with a console script, so [uv](https://docs.astral.sh/uv/)
can run it straight from the git repo — no clone, no venv:

```sh
uvx --from git+https://github.com/Yasirrazaa/archon archon --help
```

Examples:

```sh
uvx --from git+https://github.com/Yasirrazaa/archon archon plugins --ci
uvx --from "archon @ git+https://github.com/Yasirrazaa/archon" archon scan --target https://api.example.com/v1 --ci
```

Requirements (guarded by `tests/distribution/test_packaging.py::TestUvxPackaging`):

- `pyproject.toml` declares `[project.scripts] archon = "archon_cli.main:main"`.
- The hatchling build backend produces a wheel that packages `packages/archon_cli`.
