# ADR 0005 — One-shot enrollment, renewal-ready by construction

- Status: Accepted
- Date: 2026-06-26
- Builds on: ADR 0003

## Context

Long-running services eventually want cert rotation, but renewal is real scope
and, under the Puppet protocol, needs CA-side re-issue (re-key + re-submit CSR;
the CA must revoke/clean the prior cert). There is no short-lived-cert consumer
yet.

## Decision

`agent.Enroll(ctx, Config) (*Identity, error)` is **one-shot**: it produces the
current cert (default lifetime = Puppet's 5y `ca_ttl`). But the design is
**renewal-ready**: `Identity`'s `*tls.Config`s use `GetCertificate` /
`GetClientCertificate` callbacks that read the Identity's *current* cert behind a
lock, so a future background renewer can hot-swap the cert with **no API change**
to consumers.

No renewal goroutine and no CA re-issue semantics are built now.

## Consequences

- Consumers hold a live `*tls.Config` that will transparently pick up a rotated
  cert if/when a renewer is added.
- Adding renewal later is additive: a `Manage()`/renewer plus CA re-enroll
  support, decided in its own ADR when a concrete need exists.
- `ctx` is threaded through enrollment so `--waitforcert` polling is
  cancellable.
