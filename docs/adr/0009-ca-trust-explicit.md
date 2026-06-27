# ADR 0009 — Explicit CA trust in the library; TOFU is opt-in

- Status: Accepted
- Date: 2026-06-26
- Builds on: ADR 0003, ADR 0008

## Context

The CLI trusts the CA on first use (InsecureSkipVerify for the first
`/certificate/ca` fetch), like a Puppet agent. Acceptable for a CLI; a sharp
edge for a library that could silently trust an unverified CA.

## Decision

The `agent` library establishes trust **explicitly**. `agent.Config` carries
either:

- a pinned CA — `CACert []byte` (PEM) or `CAFingerprint string`, verified before
  any enrollment traffic; or
- `TrustOnFirstUse bool` — an explicit opt-in to fetch-and-trust the CA on first
  contact.

The library **never** TOFUs silently: with neither a pin nor `TrustOnFirstUse`,
`Enroll` errors. `facts-ca-cli` sets `TrustOnFirstUse: true`, so its
Puppet-agent behavior (and CLI contract) is unchanged.

## Consequences

- Production consumers pin the CA; dev/ephemeral consumers opt into TOFU
  knowingly.
- The CLI still reuses the library's CA-fetch path (no duplicated TOFU).
- When `CAFingerprint` is set, the fetched CA is accepted only if its fingerprint
  matches — a middle ground between blind TOFU and shipping the full PEM.
