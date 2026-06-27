# ADR 0007 — Identity yields both mTLS directions; strict inbound

- Status: Accepted
- Date: 2026-06-26
- Builds on: ADR 0003, ADR 0005

## Context

A consumer service may make outbound mTLS calls, accept inbound mTLS, or both.
mTLS exists to reject peers without a CA-signed cert.

## Decision

`*Identity` exposes:

- `ClientTLSConfig(serverName string) *tls.Config` — outbound: presents the
  enrolled cert, verifies the server against the pinned CA.
- `ServerTLSConfig() *tls.Config` — inbound: presents the enrolled cert,
  `ClientCAs` = pinned CA, **`RequireAndVerifyClientCert`** (only CA-signed peers
  connect).
- Conveniences: `HTTPClient() *http.Client`, `Listener(addr) (net.Listener, error)`.
- Raw accessors: `Certificate()`, `PrivateKey()`, `CAPool()`.

Both configs use the `GetCertificate`/`GetClientCertificate` callbacks from
ADR 0005 (renewal-ready).

## Consequences

- Strict inbound is the secure default for a mesh; a verify-if-given variant can
  be added if a consumer needs anonymous routes.
- This is the agent/consumer identity. The **CA half's** own listener is
  separate and stays verify-if-given (ADR 0004) so fresh agents can bootstrap
  without a cert.
