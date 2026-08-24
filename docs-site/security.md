# Security

Archon treats every request as potentially hostile. The full threat model lives in
[`SECURITY.md`](https://github.com/Yasirrazaa/archon/blob/main/SECURITY.md) — this page is
the short version.

## Trust model (summary)

- **Trusted:** the armor process and its pinned dependencies; registry `AgentCard`
  records once loaded; the operator-configured upstream endpoint.
- **Not trusted:** request bodies, caller-supplied headers (`X-Agent-ID` alone grants
  nothing), caller timestamps, or prompt content claiming authority.

## Defense-in-depth

- HMAC-signed requests: body-bound signatures with a ±300 s replay window
  (`HmacVerifier`); signed mode is enforced by the container entry point.
- Guard pipeline on every request: normalization → threat classification → trust
  segmentation → spotlighting → execution-mode wrapping, plus output guardrails.
- Token-bucket rate limiting keyed by authenticated agent id (HTTP 429 on excess).

## Known limitations (selected — full list in SECURITY.md §4)

- Default SQLite stores are single-process and ephemeral; use Postgres in production.
- No internal TLS — terminate TLS at the platform front door; never expose uvicorn
  publicly.
- No nonce store: same-signature replay works within the timestamp window.
- Registry integrity is unverified — protect storage; anyone who can write the registry
  can mint identities.

See SECURITY.md §6 for the pre-production hardening checklist.

## Reporting a vulnerability

**Do not open public GitHub issues for security reports.**

Contact **security@archon.dev** (placeholder until domain is confirmed) and use the
[security advisory template](https://github.com/Yasirrazaa/archon/blob/main/.github/ISSUE_TEMPLATE/security_advisory.md).
Expected response: acknowledgement within 2 business days, triage within 7 days, fix
target 30 days for high/critical findings. Coordinated disclosure with up to 90 days for
a fix before publication; reporters are credited unless they prefer anonymity. Full
process in [`SECURITY.md`](https://github.com/Yasirrazaa/archon/blob/main/SECURITY.md) §5.
