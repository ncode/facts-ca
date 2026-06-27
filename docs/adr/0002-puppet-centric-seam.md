# ADR 0002 — Puppet-CA-centric, no pluggable-protocol abstraction

- Status: Accepted
- Date: 2026-06-26
- Builds on: ADR 0001

## Context

A "full toolkit" could be protocol-agnostic (Enroller / CA-protocol interfaces
with Puppet as one implementation, leaving room for ACME/SPIFFE/Vault/step-ca)
or Puppet-CA-centric (concrete types for the one protocol we support). There is
no second CA protocol planned; the project's entire value is Puppet wire
compatibility.

## Decision

The toolkit is **Puppet-CA-centric**. It ships concrete types for the Puppet CA
v1 protocol with **no interface machinery for pluggable backends**. "Reuse for
other services" means other services speak the *same* Puppet CA v1 protocol to
get mTLS — not that other CA protocols plug in.

## Consequences

- The shared core stays concrete: `pki` (X.509 primitives) and the Puppet wire
  contract (`capi`, `ppext`).
- No `Enroller`/`Provider` interfaces, no registry, no plugin loading. If a real
  non-Puppet backend ever appears, introduce the seam then (a later ADR), driven
  by a concrete second implementation rather than speculation.
- Keeps the public surface small and the abstraction honest.
