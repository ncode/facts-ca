# ADR 0006 — Agent storage: disk optional, ephemeral by default when unset

- Status: Accepted
- Date: 2026-06-26
- Builds on: ADR 0002, ADR 0005

## Context

Bare-metal Puppet hosts expect a persisted ssldir; containerized/12-factor
services often prefer not to write keys to disk. The Identity already holds
cert+key in memory after enrollment, so both are cheap to support.

## Decision

`agent.Config.Dir` is **optional**:

- **Set** — enrollment reads/writes the Puppet ssldir at that path (compat with
  real Puppet, and caches the identity across restarts).
- **Empty** — **ephemeral**: enroll fresh in memory on each start, persist
  nothing, return the Identity directly.

No `Store` interface is introduced (keeps ADR 0002's lean stance); it is just
"dir or no dir." The CA half remains disk-backed (`cadir`) — a CA's issued-cert,
serial and CRL state must be durable — with `t.TempDir()` for tests.

## Consequences

- One code path branches on whether `Dir` is empty; the ssldir writer becomes an
  internal detail used only when persisting.
- Ephemeral mode trivially supports read-only-filesystem and secret-less pods.
- If a non-disk persistent backend (k8s Secret, Vault) is ever needed, revisit
  with a real implementation (future ADR), not before.
