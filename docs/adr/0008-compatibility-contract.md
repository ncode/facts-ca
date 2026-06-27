# ADR 0008 — Freeze the CLI/wire contract; let the library API evolve

- Status: Accepted
- Date: 2026-06-26
- Builds on: ADR 0001

## Context

The refactor must not regress what users and Puppet already depend on, but we
also want the cleanest possible library API.

## Decision

Two independent contracts:

1. **Frozen** — the binaries' CLI (flags, output) and the Puppet CA v1 wire
   behavior. `./e2e.sh` and `./interop.sh` must pass unchanged. The reference
   binaries are thin adapters that preserve their existing UX.
2. **Free to evolve** — the library's Go API (`agent`, `ca`, `pki`, `Identity`,
   `Config`, `Options`). Pre-1.0 (v0.x); breaking changes allowed between
   minors until v1.

These do not conflict: a binary owns its CLI contract and maps it onto whatever
the library API currently is, so the API can change without the CLI changing.

## Consequences

- The binaries double as living proof the facades are sufficient and ergonomic
  (if a CLI feature can't be expressed cleanly on the API, the API is wrong).
- The existing test scripts are the regression gate for contract #1.
- Library versioning starts at v0.x with an explicit "API unstable until v1"
  note.
