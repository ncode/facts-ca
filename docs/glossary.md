# Glossary

Ubiquitous language for the facts-ca toolkit. Terms are added/sharpened as
design decisions land (see `docs/adr/`).

- **Toolkit** — the facts-ca repo viewed as a library: public packages other
  services import, with the two binaries as reference implementations.
- **Agent half** — the client-side library: enroll an identity from a CA and
  obtain a usable mTLS transport. Reference implementation: `facts-ca-cli`.
- **CA half** — the server-side library: embed/run a Puppet-compatible CA that
  issues, signs, revokes and serves certificates. Reference implementation:
  `facts-ca-server`.
- **Shared core** — the only public shared package is `pki` (X.509 primitives);
  the Puppet wire contract (`capi`, `ppext`) is internal plumbing behind the
  facades.
- **Facade** — a high-level public entry point that hides the protocol:
  `agent.Enroll` and `ca.New`/`Open`. Consumers use facades, not plumbing.
- **Identity** — the value `agent.Enroll` returns: the current cert+key plus the
  pinned CA, exposing client/server `*tls.Config` and conveniences. Renewal-ready
  (its TLS configs read the current cert via callbacks).
- **Pinning** — supplying the CA up front (`CACert` PEM or `CAFingerprint`) so
  trust is verified, not assumed.
- **TOFU (trust-on-first-use)** — fetching and trusting the CA on first contact;
  an explicit opt-in (`TrustOnFirstUse`) in the library, the CLI's default.
- **Ephemeral enrollment** — enrolling with no `Dir`: identity lives only in
  memory, nothing is written to disk (for containers / read-only filesystems).
- **Enrollment** — the agent flow that turns "no identity" into "a CA-signed
  cert + private key": fetch/trust the CA, generate a key, submit a CSR, poll
  until signed, persist to an ssldir.
- **mTLS transport** — the usable output of enrollment: a `*tls.Config` (and
  conveniences like an `http.Client` / `net.Listener`) wired with the enrolled
  cert and the pinned CA, ready for mutually-authenticated connections.
- **Reference implementation** — a thin `cmd/` binary that wires the library to
  flags/filesystem and nothing more; proves the public API is sufficient.
- **Consumer service** — some other Go service that imports the toolkit to get
  mTLS identity (agent half) or to run a CA (CA half).
