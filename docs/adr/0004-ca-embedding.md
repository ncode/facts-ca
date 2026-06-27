# ADR 0004 — CA half embeds as an http.Handler with a convenience server

- Status: Accepted
- Date: 2026-06-26
- Builds on: ADR 0003

## Context

A consumer "embeds a CA" either by mounting it on an existing server (alongside
its own routes/middleware) or by running it standalone. We need `ca.New`'s shape
to serve both without forcing either.

## Decision

`ca.New(Options) (*CA, error)`, where `*CA` exposes:

- `Handler() http.Handler` — the Puppet CA v1 routes, to mount on the consumer's
  own mux/server.
- `ServerTLSConfig() *tls.Config` — the mTLS server config (CA-signed leaf,
  ClientCAs = the CA, verify-if-given) for the listener.
- `ListenAndServe(addr string) error` — batteries-included standalone serving,
  used by `facts-ca-server`.

Plus the existing admin operations (sign/revoke/list/clean) as methods.

## Consequences

- Composable (add routes, share a port, inject observability) and one-line
  standalone both work.
- The split between agent-reachable routes and mTLS-gated admin routes stays an
  internal concern of `Handler()`.
- `facts-ca-server` shrinks to flag parsing + `ListenAndServe`.
