---
name: Security advisory
about: Coordinated vulnerability disclosure for archon-armor / archon-core
title: "[Security] "
labels: security
assignees: ''

---

> **Do not open public GitHub issues for security reports if you need confidentiality.**
> Prefer emailing **security@archon.dev** (placeholder until domain is confirmed) with the
> details below. This template exists so reports arrive structured; the coordinated
> disclosure process, response-time commitments, and credit policy are defined in
> [`SECURITY.md` §5](https://github.com/Yasirrazaa/archon/blob/main/SECURITY.md).

## Title

<!-- One-line summary of the vulnerability. -->

## Affected component(s)

<!-- e.g. packages/archon_armor (proxy), packages/archon_core/security/authn.py (HmacVerifier), CLI subcommand, container image tag. -->

## Affected version(s)

<!-- Branch/commit SHA, release tag, or image digest you tested against. -->

## Severity

<!-- Your assessment: low / medium / high / critical, plus a CVSS v3/v4 vector string and score if you have one. If you'd like us to score it instead, say "requesting CVSS assessment". -->

## Description

<!-- What is wrong, what is the security impact, and which trust-boundary assumption does it violate? See SECURITY.md §1 for the trust model. -->

## Reproduction

<!-- Minimal steps or PoC to trigger the issue. Include exact commands, request bodies/headers, and observed vs. expected behavior. Redact any secrets. -->

```bash
# commands here
```

## Suggested mitigation (optional)

## Reporter contact

<!-- Name/handle for credit in release notes, or state "prefer anonymity". Optional: timezone for coordination. -->

## Disclosure timeline

Per SECURITY.md §5 we practice **coordinated disclosure**: acknowledgement within 2
business days, triage within 7 days, fix/mitigation target 30 days for high/critical,
and up to 90 days before public publication of details.
