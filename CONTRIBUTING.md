# Contributing to Facts CA

facts-ca is a Go port of the Puppet CA: `facts-ca-server` and `facts-ca-cli`
speak the Puppet CA v1 HTTP API over mTLS, store state in a Puppet-compatible
`ssldir`/`cadir`, and interoperate with a real puppetserver. This page is how to
work on it.

## Development setup

facts-ca needs Go 1.26+ (the module targets `go 1.26.4`). Build and test with
the Go toolchain:

```sh
go build ./cmd/facts-ca-server
go build ./cmd/facts-ca-cli
go test ./...
go test -race ./...
```

`gofmt` and `go vet` must be clean before you push; CI checks both. Two
out-of-process proofs back the unit tests and should pass locally:

```sh
./e2e.sh      # builds both binaries, runs the server over TLS, bootstraps a
              # cert with trusted-fact extensions, and asserts the result
./interop.sh  # runs a real puppet/puppetserver container and proves wire
              # interop (needs Docker and openssl)
```

## Test-driven development

Every behavior starts with a failing Go test, then the minimal code to pass it.

- Unit-test the library through the `internal/` packages: `internal/capi` (the
  wire contract), `internal/pki` (X.509 primitives), `internal/castore` (the
  server-side `cadir`), `internal/ssldir` (the agent-side store), and
  `internal/ppext` (Puppet extension OIDs). Keep tests next to the package they
  exercise.
- Prefer integration-style tests that drive a real code path over mocks. The
  wire- and disk-level contracts are proven end to end by `./e2e.sh` (server +
  CLI over the wire) and `./interop.sh` (against a live puppetserver).
- Make platform- and environment-dependent behavior testable through seams:
  inject the clock, the filesystem root (`cadir`/`ssldir`), and the HTTP client
  rather than reaching for globals.

## Wire and on-disk compatibility

facts-ca's contract is byte- and wire-compatibility with Puppet. That is the
rule that governs every change:

- The HTTP surface MUST stay the documented Puppet CA v1 API:
  `certificate/:name` (including `ca`), `certificate_request/:name`
  (PUT/GET/DELETE), `certificate_revocation_list/ca`, and the admin
  `certificate_status[es]` endpoints. PEM is served as `text/plain`.
- On-disk files MUST match Puppet's layout: the agent `ssldir`
  (`private_keys/`, `public_keys/`, `certs/`, `certificate_requests/`,
  `crl.pem`) and the server `cadir` (`ca_crt.pem`, `ca_key.pem`, `ca_crl.pem`,
  `serial`, `inventory.txt`, `signed/`, `requests/`). PEM encodings (PKCS#1
  private keys, PKIX public keys) MUST byte-match what OpenSSL/Puppet write.
- Trusted-fact extensions MUST stay within Puppet's registered OID arc
  (`1.3.6.1.4.1.34380.1.*`) with DER `UTF8String` values, and the CA MUST drop
  anything outside it, exactly as puppetserver does.

Any change touching the API, the file layout, or the extension encoding MUST be
covered by a test and — where it can be — proven against a real puppetserver in
`./interop.sh`. Deliberate deviations from Puppet are documented in the README's
"Known simplifications" section and pinned by a test; don't introduce a silent
one.

## Platform scope

facts-ca is pure Go with no cgo, so both binaries build and run anywhere the Go
toolchain targets (Linux, macOS, Windows, and the BSDs). Development and CI run
on Linux and macOS.

Interop testing needs a real `puppet/puppetserver` image, which is published for
amd64 only. On GitHub's `ubuntu-latest` (amd64) runners it runs natively; on
Apple Silicon the compose file pins `platform: linux/amd64`, so the first boot
is slow under emulation.

## Interop and end-to-end gates

Two scripts are the blocking integration gates and must pass before a change
that touches behavior is merged:

- `./e2e.sh` builds both binaries, starts `facts-ca-server` over TLS, has
  `facts-ca-cli` bootstrap a cert (with trusted-fact extensions) over the wire,
  exercises the mTLS admin and data paths, and verifies the chain with openssl.
- `./interop.sh` stands up a real `puppet/puppetserver` via `docker-compose.yml`,
  bootstraps `facts-ca-cli` against it with extensions, asserts puppetserver
  copied them into the issued cert, and makes an mTLS request back to it.

CI runs `go test ./...`, `go vet`, and a `gofmt` check on every push, plus the
interop job on amd64 runners.

## Parity questions

The reference is a real puppetserver, not our reading of it. Compatibility is
judged at the wire and on-disk boundary: a CSR, certificate, CRL, HTTP response,
or `ssldir`/`cadir` file produced by facts-ca should be indistinguishable from
puppetserver's, and `./interop.sh` is how you check. When a behavior cannot be
made identical, the deviation is recorded in the README's "Known simplifications"
section and pinned by a test, so it is a deliberate, visible choice rather than
a silent one. Don't re-litigate a documented deviation per change; supersede it
in the README if the decision changes.

## Where decisions live

- `README.md` is the operator- and protocol-facing contract: the supported
  endpoints, the `ssldir`/`cadir` layout, the extension OID arc, and the
  "Known simplifications" that are deliberate deviations from Puppet.
- The package doc comments define the project's vocabulary — `capi` (wire
  contract), `pki` (X.509 primitives), `castore` (`cadir`), `ssldir` (agent
  store), `ppext` (Puppet extension OIDs). Read them before changing a package.
- `CHANGELOG.md` records what shipped, under `## Unreleased` until release.
