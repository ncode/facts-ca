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
- **Autosign policy executable** — an operator-provided program that receives a
  normalized CSR description and returns an approve/deny decision. It does not
  choose TTLs, SAN handling, extensions to copy, or any other signing behavior.
  A denial leaves the CSR pending for manual review instead of rejecting or
  deleting it. The policy input is a JSON document on stdin, including decoded
  Puppet extension requests and raw CSR extension data. The policy output is its
  exit status: `0` approves, `1` denies, and any other outcome is a policy error.
  Policy errors are reported to operators and leave the CSR pending; CSR
  submission still succeeds from the enrolling agent's point of view. Policy
  autosign is still autosign: the policy only participates when automatic
  signing is enabled, and narrows what would otherwise be blanket autosigning.
  Configuring a policy while automatic signing is disabled is invalid. Policy
  input is the CA's normalized view of the CSR; the raw CSR PEM is not part of
  the policy contract. Policy input also includes request context needed for
  approval decisions, including the direct TCP peer IP as the request source IP.
  Proxy-provided client identity is out of scope until trusted PROXY protocol
  support is explicitly added. Request context lives under a separate `request`
  object in the versioned policy input JSON. Subject alternative names are
  exposed as typed DNS and IP arrays rather than Puppet display strings. The CSR
  subject is represented by the validated `certname`, not by a full X.509
  subject object.
  Puppet extension request keys use known Puppet short names when available and
  dotted OIDs otherwise. Policy input also includes a normalized list of
  recognized CSR extensions for policies that need more than Puppet extension
  requests. Unknown non-critical extensions are omitted; unknown critical
  extensions make the CSR invalid for policy autosign. Extension values are
  exposed as decoded JSON values; raw DER extension bytes are not part of the
  policy contract. Puppet extension request values are strings, while known
  structured X.509 extensions use typed JSON values. A CSR whose recognized
  extensions cannot be decoded into the policy input is invalid for policy
  autosign and is not stored. Policy input normalization happens before the CSR
  is stored; policy execution happens after the CSR is durably stored and before
  signing. Re-submitting the same pending CSR re-runs the policy, allowing a
  later approval after external state changes. Policy execution must not hold the
  CA store lock; signing still verifies that the same CSR is pending before
  issuing a certificate. If an approved CSR changes or disappears before signing,
  the CA does not sign it.
  Policy stdout is ignored; stderr may be logged for deny/error outcomes and is
  bounded before logging. Denial/error results are not persisted in CA state;
  the CSR remains in the existing requested state. The operating system is
  responsible for policy executable permissions and ownership. The policy
  process inherits the server environment; stdin JSON remains the policy data
  contract. The executable is invoked without arguments; operators who need
  arguments can use a wrapper script. The policy process inherits the server
  working directory. Configuration names use `AutosignPolicyExecutable` in the
  library and `-autosign-policy-executable` in the server CLI; policy timeout
  names are `AutosignPolicyTimeout` and `-autosign-policy-timeout`. The policy
  executable path must be absolute. Startup validates that a configured policy
  executable exists and is not a directory; later execution failures are policy
  errors. Configuring a policy timeout without a policy executable is invalid.
