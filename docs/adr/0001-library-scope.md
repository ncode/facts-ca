# ADR 0001 — Library scope: a full mTLS-enrollment toolkit, both halves

- Status: Accepted
- Date: 2026-06-26

## Context

facts-ca today is two binaries (`facts-ca-cli`, `facts-ca-server`) plus `internal/`
packages. Nothing is importable by another module, and the genuinely reusable
behavior — the agent enrollment flow (TOFU CA fetch → key → CSR → poll) and the
mTLS transport builders on the client, and the HTTP CA handlers + TLS config on
the server — lives inside the two `main()` functions.

We want the repo to be a reusable library so other services can adopt the same
Puppet-CA-style mTLS-enrollment pattern.

## Decision

The repo becomes a **toolkit**: both halves are first-class, public Go libraries
over a shared PKI/protocol core.

- **Agent half** — a service enrolls and obtains a usable mTLS identity.
- **CA half** — a service embeds/runs a Puppet-compatible CA.
- **Shared core** — PKI primitives and the Puppet CA v1 wire contract.

`facts-ca-cli` and `facts-ca-server` become thin reference implementations of the
two halves.

## Consequences

- Reusable behavior must move out of `main()` into packages, and the importable
  packages must move out of `internal/`.
- We take on a public API surface (and its stability obligations) for both
  halves plus the shared core — more to design and keep stable than a narrow
  agent-only library would have been.
- Open questions this opens (subsequent ADRs): how Puppet-specific vs
  protocol-agnostic the seam is, module/package layout, the public API shape of
  each half, versioning commitment, and how the binaries stay thin.
