## ADDED Requirements

### Requirement: Create or load a CA

The `ca` package SHALL provide `Init(Options) (*CA, error)` to create a new
Puppet-compatible CA in `Options.Dir` (a durable cadir) and `Open(Options)
(*CA, error)` to load an existing one.

#### Scenario: Init creates a fresh CA

- **WHEN** `Init` runs against an empty directory
- **THEN** it generates the CA key and self-signed certificate and writes the
  cadir layout (ca cert/key, serial, CRL, signed/ and requests/)

#### Scenario: Init refuses to clobber an existing CA

- **WHEN** `Init` runs against a directory that already holds a CA certificate
- **THEN** it returns an error rather than overwriting

### Requirement: Mountable Puppet CA v1 handler

`*CA` SHALL expose `Handler() http.Handler` serving the Puppet CA v1 routes so a
consumer can mount it on its own server alongside other routes. The handler SHALL
preserve the Puppet CA v1 wire behavior.

#### Scenario: A Puppet agent path is served

- **WHEN** a client requests `GET /puppet-ca/v1/certificate/ca` from the handler
- **THEN** the CA certificate is returned as PEM, matching the Puppet wire contract

#### Scenario: Admin routes require a verified client certificate

- **WHEN** a `certificate_status` admin route is called without a CA-verified
  client certificate
- **THEN** the handler responds 403

### Requirement: Standalone serving with mTLS

`*CA` SHALL expose `ServerTLSConfig() *tls.Config` (CA-signed leaf, `ClientCAs`
= the CA, verify-client-if-given so fresh agents can bootstrap without a cert)
and `ListenAndServe(addr) error` for standalone operation.

#### Scenario: An agent bootstraps over the standalone server

- **WHEN** a fresh agent with no certificate submits a CSR to a server started by
  `ListenAndServe`
- **THEN** the submission is accepted (the listener does not require a client cert)

### Requirement: Admin operations

`*CA` SHALL expose `Sign(name, opts)`, `Revoke(name)`, `Clean(name)`, and
`Statuses()` (returning a public status type, not an internal one) for managing
issued certificates.

#### Scenario: Sign then revoke

- **WHEN** a pending CSR is signed via `Sign` and later revoked via `Revoke`
- **THEN** the certificate is issued, then its serial appears in the CRL and its
  status reports revoked

### Requirement: Autosign and SAN policy options

`Options.AutosignAll` SHALL cause every valid incoming CSR to be signed
immediately, and `Options.AllowAltSAN` (default false, matching puppetserver)
SHALL control whether agent-requested subjectAltNames are honored.

#### Scenario: SANs are dropped by default

- **WHEN** `AllowAltSAN` is false and an agent CSR requests a subjectAltName
- **THEN** the issued certificate omits that SAN

### Requirement: Puppet wire compatibility is preserved

The CA half SHALL remain wire-compatible with a real puppetserver; the existing
`./interop.sh` proof SHALL pass unchanged.

#### Scenario: Interop proof passes

- **WHEN** `./interop.sh` runs against the refactored CA-backed binary
- **THEN** a real Puppet agent/CA interaction succeeds as before
