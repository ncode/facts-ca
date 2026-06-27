# agent-enrollment Specification

## Purpose
TBD - created by archiving change toolkit-refactor. Update Purpose after archive.
## Requirements
### Requirement: Enroll an identity from a Puppet-compatible CA

The `agent` package SHALL provide `Enroll(ctx, Config) (*Identity, error)` that
obtains a CA-signed certificate for the configured certname over the Puppet CA v1
protocol, generating an RSA key and CSR and retrieving the signed certificate.

#### Scenario: Successful enrollment against an autosigning CA

- **WHEN** `Enroll` is called with a reachable CA, a certname, and a trust setting
- **THEN** it returns an `*Identity` holding the issued certificate, its private
  key, and the pinned CA certificate

#### Scenario: Certname defaults to host FQDN

- **WHEN** `Config.Certname` is empty
- **THEN** enrollment uses the host FQDN as the certname

### Requirement: Explicit CA trust

`Enroll` SHALL NOT trust an unverified CA silently. Trust SHALL be established
either by a pin (`Config.CACert` PEM or `Config.CAFingerprint`) or by an explicit
`Config.TrustOnFirstUse` opt-in.

#### Scenario: Pinned CA fingerprint mismatch is rejected

- **WHEN** `Config.CAFingerprint` is set and the fetched CA certificate's
  fingerprint does not match
- **THEN** `Enroll` returns an error and performs no enrollment

#### Scenario: No pin and no TOFU is an error

- **WHEN** neither a CA pin nor `TrustOnFirstUse` is provided
- **THEN** `Enroll` returns an error without contacting the CA insecurely

#### Scenario: Trust-on-first-use is opt-in

- **WHEN** `Config.TrustOnFirstUse` is true and no pin is given
- **THEN** `Enroll` fetches the CA certificate on first contact and adopts it

### Requirement: Optional disk persistence

`Config.Dir` SHALL be optional. When set, enrollment reads and writes a
Puppet-compatible ssldir at that path and reuses an existing identity. When
empty, enrollment is ephemeral: the identity exists only in memory and nothing is
written to disk.

#### Scenario: Disk mode reuses an existing certificate

- **WHEN** `Config.Dir` points at an ssldir already containing a signed cert and key
- **THEN** `Enroll` loads and returns that identity without submitting a new CSR

#### Scenario: Ephemeral mode writes nothing

- **WHEN** `Config.Dir` is empty
- **THEN** `Enroll` completes without creating files and returns the in-memory identity

### Requirement: Trusted-fact extension requests

The agent SHALL embed `Config.Extensions` as extension requests in the submitted
CSR. Keys MAY be Puppet trusted-fact short names (such as `pp_role`) or dotted
OIDs under the Puppet extension arc.

#### Scenario: Extensions are sent in the CSR

- **WHEN** `Config.Extensions` contains `pp_role=web`
- **THEN** the submitted CSR carries the corresponding extension request and the
  issued certificate carries it when the CA copies it

### Requirement: Identity yields client and server mTLS transport

`*Identity` SHALL expose `ClientTLSConfig(serverName)` (outbound: presents the
enrolled cert, verifies the server against the pinned CA) and `ServerTLSConfig()`
(inbound: presents the enrolled cert, `ClientCAs` = pinned CA,
`RequireAndVerifyClientCert`), plus `HTTPClient()`, `Listener(addr)`, and raw
accessors. The TLS configs SHALL read the current certificate via
`GetCertificate`/`GetClientCertificate` callbacks so a future renewer can rotate
it without an API change.

#### Scenario: Inbound mTLS rejects an unsigned client

- **WHEN** a peer without a CA-signed certificate connects to a listener built
  from `ServerTLSConfig()`
- **THEN** the TLS handshake is rejected

#### Scenario: Outbound mTLS authenticates to a peer

- **WHEN** `HTTPClient()` calls a server that requires client certs from the same CA
- **THEN** the request succeeds with the enrolled identity presented

### Requirement: Issued certificate is validated before adoption

Before adopting a fetched certificate, `Enroll` SHALL verify it chains to the
pinned CA, matches the requested certname, and matches the locally generated
private key.

#### Scenario: Mismatched certificate is refused

- **WHEN** the CA returns a certificate whose public key does not match the local key
- **THEN** `Enroll` returns an error and does not adopt the certificate

### Requirement: Library does not print and is cancellable

`Enroll` SHALL NOT write to stdout/stderr; it returns errors and accepts an
optional `*slog.Logger`. Waiting for a pending certificate SHALL honor `ctx`
cancellation and `Config.WaitForCert`.

#### Scenario: Context cancellation stops waiting

- **WHEN** the certificate is not yet signed and `ctx` is cancelled while polling
- **THEN** `Enroll` returns promptly with a context error

