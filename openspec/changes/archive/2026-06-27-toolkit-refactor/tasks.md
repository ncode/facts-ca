## 1. Make pki public

- [x] 1.1 Move `internal/pki` to `pki/` and update all import paths
- [x] 1.2 Confirm `go build ./...`, `go test ./...`, and `go vet ./...` pass
- [x] 1.3 Add a `pki` example/test proving key→CSR→CA→leaf verifies standalone (pki-toolkit spec)

## 2. Extract the CA half into `ca/`

- [x] 2.1 Create `ca` package with `Options`, `Init(Options)`, `Open(Options)`, `*CA`
- [x] 2.2 Move the HTTP handlers (agent routes + mTLS-gated admin) out of `cmd/facts-ca-server` into `ca.Handler()`
- [x] 2.3 Add `CA.ServerTLSConfig()` (verify-if-given) and `CA.ListenAndServe(addr)`
- [x] 2.4 Expose `Sign`/`Revoke`/`Clean`/`Statuses` on `*CA`; re-home the public status + desired-state DTOs (`ca.Status`, `ca.DesiredState`) so no internal type appears in public signatures
- [x] 2.5 Keep `castore`, `capi`, `ppext` internal; `ca` wraps them
- [x] 2.6 Unit-test `ca`: Init refuses to clobber, handler serves `certificate/ca`, admin requires client cert, sign→revoke, autosign, SAN-dropped-by-default (embeddable-ca spec)

## 3. Rewrite facts-ca-server as a thin adapter

- [x] 3.1 Reduce `cmd/facts-ca-server/main.go` to flag parsing + `ca.Init/Open` + `ListenAndServe` + offline `list/sign/revoke/clean` + `version`
- [x] 3.2 CLI flags unchanged; stdout result lines preserved (progress now goes to the `*slog.Logger` on stderr, which is not part of the asserted contract)
- [x] 3.3 Run `./e2e.sh` and `./interop.sh`; both pass unchanged (embeddable-ca: wire compatibility)

## 4. Extract the agent half into `agent/`

- [x] 4.1 Create `agent` package with `Config`, `Enroll(ctx, Config)`, `*Identity`
- [x] 4.2 Implement explicit CA trust: `CACert`/`CAFingerprint` pin or `TrustOnFirstUse`; error when neither is set (agent-enrollment spec)
- [x] 4.3 Implement optional `Dir`: ssldir persist/reuse when set, ephemeral in-memory when empty
- [x] 4.4 Embed `Config.Extensions` as CSR extension requests; validate the issued cert (chain/CN/key) before adopting
- [x] 4.5 Implement `Identity.ClientTLSConfig`/`ServerTLSConfig` (strict) + `HTTPClient`/`Listener` + raw accessors, backed by `GetCertificate`/`GetClientCertificate` callbacks (renewal-ready)
- [x] 4.6 Make enrollment non-printing and `ctx`-cancellable with `WaitForCert`; accept an optional `*slog.Logger`; keep `ssldir` internal
- [x] 4.7 Unit-test `agent`: pinned-mismatch rejected, no-pin/no-TOFU errors, disk reuse, ephemeral writes nothing, strict inbound rejects unsigned client, ctx cancels waiting (agent-enrollment spec)

## 5. Rewrite facts-ca-cli as a thin adapter

- [x] 5.1 Reduce `cmd/facts-ca-cli/main.go` to flag parsing over `agent` (bootstrap/mtls/ca admin/version), setting `TrustOnFirstUse: true` to preserve Puppet-agent behavior
- [x] 5.2 CLI flags unchanged; stdout result lines (incl. the trusted-fact report) preserved; enrollment progress moved to the stderr logger
- [x] 5.3 Run `./e2e.sh` and `./interop.sh`; both pass unchanged

## 6. Verify, document, release

- [x] 6.1 Full gate: `gofmt -l`, `go vet ./...`, `go test -race ./...`, `go tool govulncheck ./...` all clean (`actionlint` runs in CI; not installed locally)
- [x] 6.2 Add a short "Use as a library" section to README with the agent + ca examples from `docs/library-api.md`
- [x] 6.3 Update `CHANGELOG.md`. Tag `v0.1.0` deferred to the user (no push outstanding; release after the code-review pass)
