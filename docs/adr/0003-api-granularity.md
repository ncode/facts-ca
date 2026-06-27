# ADR 0003 — Public API granularity: two facades, core hidden

- Status: Accepted
- Date: 2026-06-26
- Builds on: ADR 0001, ADR 0002

## Context

With a Puppet-centric toolkit (ADR 0002), we still choose how much surface to
expose: high-level facades, facades plus the whole core, or raw building blocks.
Every exported symbol is a stability obligation.

## Decision

Expose **two high-level facades plus `pki`**, and keep everything else internal:

- `agent.Enroll(ctx, Config) (*Identity, error)` — the enrollment half.
  `Identity` yields the mTLS transport (`TLSConfig()`, `HTTPClient()`,
  `Listener()`).
- `ca.New(Options) (*CA, ...)` — the CA half (exact shape decided in a later
  ADR), exposing an `http.Handler` for embedding.
- `pki` stays public — it is genuinely useful standalone X.509 tooling.
- `capi`, `ppext`, `castore`, `ssldir`, `version` become **internal**
  implementation detail behind the facades.

## Consequences

- A consumer needs ~3 lines and zero Puppet-protocol knowledge for either half.
- Refines ADR 0001: the "shared core" is public only as `pki`; the Puppet wire
  contract (`capi`, `ppext`) is hidden behind the facades, not a public surface.
- Internalizing `castore`/`ssldir` means their current exported types become an
  implementation detail we can change freely; only the facade types are stable.
- We must design the facade types (`Config`, `Identity`, `Options`, `CA`)
  carefully — they are the contract.
