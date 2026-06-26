# Security Policy

## Supported Versions

Security fixes are provided for the latest tagged release and `main`. facts-ca
has not yet published a tagged release; until the first `v0` tag is cut, fixes
land on `main`.

| Version | Supported |
| ------- | --------- |
| `main`  | Yes       |

## Reporting a Vulnerability

Report vulnerabilities through GitHub private vulnerability reporting for
`ncode/facts-ca`. Do not open a public issue.

facts-ca is a certificate authority: a flaw in how it generates keys, builds or
signs certificates, validates CSRs, copies certificate extensions, issues or
honors revocation, or authenticates the admin API can compromise every identity
it has ever issued. Treat any such finding as sensitive and disclose it
privately first.

Include enough detail to reproduce the issue:

- affected version or commit
- platform and architecture
- the command, CA or agent config, CSR or certificate, `ssldir`/`cadir`
  contents, or Puppet CA v1 HTTP/mTLS request involved
- expected impact (for example: unauthorized issuance, private-key disclosure,
  signature or chain-validation bypass, revocation that is not honored, or an
  admin-API authorization bypass)
- proof of concept if available

We acknowledge reports within 7 days and send status updates at least every 30
days. We coordinate public disclosure after a fix is available: accepted reports
are coordinated with you in the private report, and declined reports are
explained.

## Scope

In scope are vulnerabilities in Facts CA itself: the `facts-ca-server` and
`facts-ca-cli` binaries, the Go packages under `internal/`, the release
artifacts, and the handling of operator- and agent-supplied inputs — certnames,
CSRs and their `extension_requests`, `csr_attributes.yaml` files, the
trusted-fact extension OIDs, Puppet CA v1 HTTP requests, the TLS/mTLS handshake,
and the contents of an `ssldir` or `cadir`. Errors in certificate issuance,
signing, revocation, CRL generation, key handling, or admin-API authorization
are always in scope.

Out of scope are general host and deployment misconfiguration (for example,
exposing the CA on an untrusted network, weak file permissions on a `cadir`, or
an operator's external TLS termination), the documented limitations in the
README's "Known simplifications" section (such as all-or-nothing autosign, the
unlocked `serial` file, and "any CA-signed client cert" admin authorization),
and third-party systems reached or run alongside Facts CA (a real puppetserver,
the JVM, Docker, or Puppet agents). Behavior that matches a documented
limitation is not a vulnerability; if a documented limitation turns out to have
worse impact than stated, that gap is in scope.
