## Why

facts-ca's genuinely reusable behavior — the agent enrollment flow and mTLS
transport, and the CA's HTTP handlers and serving — is currently trapped inside
two `main()` functions, and every package is under `internal/`, so no other
service can adopt the Puppet-CA-style mTLS-enrollment pattern. We want the repo
to be a library: other services should get a CA-signed mTLS identity, or embed a
Puppet-compatible CA, in a few lines. The design is settled in `docs/adr/0001`–
`0009` and `docs/library-api.md`.

## What Changes

- Introduce a public `agent` package: `Enroll(ctx, Config) (*Identity, error)`,
  one-shot but renewal-ready (TLS via `GetCertificate` callbacks). `Identity`
  yields outbound and inbound mTLS (`ClientTLSConfig`, `ServerTLSConfig` with
  strict `RequireAndVerifyClientCert`) plus `HTTPClient`/`Listener` conveniences.
- Introduce a public `ca` package: `Init`/`Open(Options) (*CA, error)`, with
  `Handler() http.Handler`, `ServerTLSConfig()`, `ListenAndServe(addr)`, and the
  sign/revoke/clean/list admin operations.
- Make `pki` a public package (X.509 primitives), keeping its current surface.
- **BREAKING (Go API only)**: move `capi`, `ppext`, `castore`, `ssldir`,
  `version` to remain `internal/`; the enrollment/serving logic moves out of
  `cmd/` into `agent`/`ca`. No external API existed before (all `internal/`), so
  no downstream Go consumer breaks.
- Trust becomes explicit: `agent.Config` pins the CA (`CACert`/`CAFingerprint`)
  or opts into `TrustOnFirstUse`; the library never silently TOFUs.
- `Config.Dir` is optional: Puppet ssldir on disk when set, ephemeral in-memory
  when empty.
- The library never prints; it returns errors and takes an optional
  `*slog.Logger`. All user-facing output stays in the binaries.
- `facts-ca-cli` and `facts-ca-server` become thin adapters over `agent`/`ca`,
  with their CLI flags/output unchanged.

Non-goals (deferred until a real need): a certificate-renewal loop and CA
re-issue semantics; multi-replica / shared-storage / non-disk CA backends;
pluggable non-Puppet protocols. Library stays pre-1.0 (v0.x).

## Capabilities

### New Capabilities
- `agent-enrollment`: enroll an identity from a Puppet-compatible CA and obtain a
  usable mTLS transport — config, explicit CA trust (pin/TOFU), disk-or-ephemeral
  storage, one-shot/renewal-ready issuance, and the `Identity` client/server TLS
  surface.
- `embeddable-ca`: run/embed a Puppet-compatible CA — `Init`/`Open`, the mountable
  `http.Handler`, `ServerTLSConfig`/`ListenAndServe`, and sign/revoke/clean/list,
  while preserving the Puppet CA v1 wire contract.
- `pki-toolkit`: the public X.509 primitives package (keys, CSRs, CA/leaf signing,
  CRLs, fingerprints, PEM I/O) usable standalone.

### Modified Capabilities
<!-- None: openspec/specs/ has no baseline specs; all capabilities are new. -->

## Impact

- Code: new `agent/`, `ca/`, `pki/` packages; `internal/{capi,ppext,castore,
  ssldir,version}`; `cmd/facts-ca-cli` and `cmd/facts-ca-server` rewritten as
  thin adapters. Wire DTOs that appear in public signatures (cert status,
  desired-state) are re-homed public.
- Contracts: the binaries' CLI (flags/output) and the Puppet CA v1 wire behavior
  are FROZEN — `./e2e.sh` and `./interop.sh` are the regression gate and must
  pass unchanged.
- Module: `github.com/ncode/facts-ca` gains public import paths
  (`.../pki`, `.../agent`, `.../ca`); versioning starts at v0.x.
- Dependencies: none added (stdlib + existing `golang.org/x/vuln` tool dep).
