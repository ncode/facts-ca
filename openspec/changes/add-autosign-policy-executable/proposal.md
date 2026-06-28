## Why

Blanket `-autosign` signs every valid CSR, including CSRs that self-assert
trusted-fact extensions. Real deployments need automatic signing gated by an
external source of truth such as a CMDB, without losing the current manual
pending-CSR fallback.

## What Changes

- Add policy-gated autosign to the CA half: `-autosign` remains the explicit
  enablement switch, and an optional autosign policy executable can narrow which
  CSRs are automatically signed.
- Add `AutosignPolicyExecutable` and `AutosignPolicyTimeout` options to the CA
  library and matching server flags.
- Pass a versioned normalized JSON view of the CSR and request context to the
  policy executable on stdin.
- Interpret policy exit status only: `0` approves, `1` denies, anything else is
  a policy error.
- Leave denied/error CSRs pending for manual review and later resubmission.
- Reject invalid policy configuration and CSRs whose policy input cannot be
  normalized safely.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `embeddable-ca`: add policy-gated autosign behavior to CSR submission and
  standalone server configuration.

## Impact

- Public API: `ca.Options` gains autosign policy executable and timeout fields.
- CLI: `facts-ca-server` gains `-autosign-policy-executable` and
  `-autosign-policy-timeout`.
- CA store/handler: CSR submission must pass direct TCP source IP into autosign
  policy evaluation.
- Tests: focused unit tests for policy JSON, exit-status handling, config
  validation, pending behavior, timeout/error behavior, and idempotent
  resubmission.
