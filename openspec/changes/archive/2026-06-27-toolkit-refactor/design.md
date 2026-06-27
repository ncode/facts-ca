## Context

facts-ca is two binaries plus `internal/` packages; the reusable behavior lives
in the two `main()` functions and nothing is importable. The full design was
settled in a grilling session and recorded in `docs/adr/0001`–`0009`,
`docs/library-api.md`, and `docs/glossary.md` — this document summarizes it and
the migration; those ADRs are the source of truth for rationale.

## Goals / Non-Goals

**Goals:**
- Public `agent`, `ca`, `pki` packages; a consumer gets inbound+outbound mTLS, or
  an embedded CA, in ~3 lines with zero Puppet-protocol knowledge.
- Binaries become thin adapters; their CLI and the Puppet wire behavior are
  preserved (`./e2e.sh`, `./interop.sh` pass unchanged).

**Non-Goals:**
- Certificate renewal loop / CA re-issue semantics (renewal-ready, not renewing).
- Multi-replica / shared-storage / non-disk CA backends.
- Pluggable non-Puppet protocols (no interfaces; Puppet-centric).
- v1 API stability (pre-1.0, v0.x).

## Decisions

Each row links to its ADR; see those for alternatives-considered.

- **Full toolkit, both halves** over a shared core (ADR 0001).
- **Puppet-centric, lean** — concrete types, no plugin interfaces (ADR 0002).
- **Two facades + public `pki`**; `capi`/`ppext`/`castore`/`ssldir`/`version`
  internal (ADR 0003).
- **CA embeds as `http.Handler`** + `ServerTLSConfig`/`ListenAndServe` (ADR 0004).
- **One-shot, renewal-ready** via `GetCertificate` callbacks (ADR 0005).
- **`Dir` optional** — disk ssldir or ephemeral in-memory (ADR 0006).
- **Identity yields both mTLS directions, strict inbound** (ADR 0007).
- **Freeze CLI/wire, evolve library API** (ADR 0008).
- **Explicit CA trust; TOFU opt-in** (ADR 0009).

Public-API constraint: public packages must not expose `internal` types, so the
wire DTOs that surface in signatures (cert status, desired-state) are re-homed
into the public `ca`/`agent` packages; `pki` types are usable because `pki` is
public.

## Risks / Trade-offs

- **Internalizing exported types silently changes behavior** → the existing
  package tests move with the packages; `./e2e.sh` + `./interop.sh` gate the
  observable contract; CI (race, vet, govulncheck) stays green.
- **Re-homing wire DTOs could drift the JSON shape** → keep the same json tags;
  `interop.sh` against a real puppetserver catches any drift.
- **Ephemeral mode + GetCertificate callbacks add a code path** → unit-test both
  disk and ephemeral enrollment and the callback-backed TLS configs.
- **CLI behavior regressions during the rewrite** → adapters are mechanical;
  e2e/interop are the regression gate, run after each step.
- **Single-writer CA limitation persists** (per-process mutex, unlocked serial)
  → documented as-is; out of scope (Non-Goals).

## Migration Plan

Incremental, each step keeps `go build`, `go test`, `./e2e.sh` green:

1. Make `pki` public (move `internal/pki` → `pki`); update imports.
2. Extract the CA HTTP handlers + serving from `cmd/facts-ca-server` into `ca`
   (`Init`/`Open`/`Handler`/`ServerTLSConfig`/`ListenAndServe`/admin); re-home the
   public status/desired-state DTOs; keep `castore`/`capi`/`ppext` internal.
3. Rewrite `cmd/facts-ca-server` as a thin adapter over `ca` (flags/output frozen).
4. Extract the enrollment flow + mTLS transport from `cmd/facts-ca-cli` into
   `agent` (`Config`/`Enroll`/`Identity`), implementing explicit trust, optional
   `Dir`, and renewal-ready callbacks; keep `ssldir` internal.
5. Rewrite `cmd/facts-ca-cli` as a thin adapter over `agent` (flags/output frozen).
6. Run `./e2e.sh` and `./interop.sh`; confirm CI checks (vet, race, govulncheck,
   actionlint) still pass. Tag `v0.1.0`.

Rollback: the change is additive-then-cutover; revert the cutover commits to
restore the previous binaries.

## Open Questions

- Exact home for the re-homed wire DTOs: a public `ca`-local type vs a slim public
  shared package. Decide during step 2; default to `ca`-local.
- Whether `pki`'s current surface needs trimming before it becomes a public
  stability obligation (e.g., hide niche helpers). Default: keep as-is for v0.x.
