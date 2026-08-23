# Archon Contrib Pack Gallery

Community-contributed probe packs. Each `*.py` file defines a module-level
`PROBES` list of `archon_armor.probes.Probe` entries and is loaded at runtime:

```bash
export ARCHON_CONTRIB_DIR=/path/to/repo/contrib
archon plugins --ci          # packs appear in the inventory
archon scan --registry ./registry.db --agent-id my-agent --pack finance_pack --ci
```

Rules for contributions (enforced by `tests/armor/test_contrib_gallery.py`):

- Module-level `PROBES: list[Probe]` — import `Probe` from `archon_armor.probes`.
- Every probe name carries the pack namespace prefix (`fin_`, `hc_`, `ops_`).
- Category starts with `contrib_` so reports group community findings separately.
- At least 5 probes; unique names; non-trivial payloads.
- No duplicate registration with built-in packs.

## Index

| File | Focus | Probes |
|---|---|---|
| `finance_pack.py` | Wire fraud, earnings leaks, SOX tampering, KYC bypass | 6 |
| `healthcare_pack.py` | PHI extraction, prescription tampering, consent bypass | 6 |
| `devops_pack.py` | CI poisoning, secret harvesting, destructive ops | 6 |

## Submitting a pack

1. Fork, add `yourdomain_pack.py` following the rules above.
2. Run `uv run pytest tests/armor/test_contrib_gallery.py -q` — all green.
3. Add your row to the index table.
4. Open a PR. MIT licensed, vendor-neutral — no cloud account required.
