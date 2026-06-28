# ADR 0010 — Gate autosign with a policy executable

- Status: Accepted
- Date: 2026-06-28
- Builds on: ADR 0004, ADR 0008

## Context

`-autosign` currently signs every valid incoming CSR. That is useful for labs,
but unsafe for real deployments because a node can self-assert trusted-fact
extensions. Operators need automatic signing that can ask an external source of
truth, such as a CMDB, before issuing a certificate.

## Decision

Keep `-autosign` as the explicit switch for automatic signing. When
`AutosignPolicyExecutable` / `-autosign-policy-executable` is also configured,
the CA builds the policy input before storing the CSR, then runs that executable
after durably storing the CSR and before signing.

The executable receives a normalized JSON document on stdin and no argv. The
document contains:

- `version: 1`
- `certname`
- `request.source_ip`, from the direct TCP peer
- typed DNS/IP subject alternative names
- decoded Puppet `extension_requests`
- a normalized decoded list of recognized CSR extensions

The raw CSR PEM and raw DER extension bytes are not part of the policy contract.
Extension values are decoded JSON values: Puppet extension request values are
strings, and known structured X.509 extensions use typed JSON values. Unknown
non-critical extensions are omitted; unknown critical extensions make the CSR
invalid for policy autosign. If the CA cannot decode recognized extensions into
that normalized JSON view, the CSR is invalid for policy autosign and is not
stored.

The executable's exit status is the protocol:

- `0` approves signing
- `1` denies autosign and leaves the CSR pending
- any other exit status, timeout, or execution error is a policy error and
  leaves the CSR pending

Policy errors and denials are logged for operators, with bounded stderr; stdout
is ignored. Policy results are not persisted as CA state.

Policy execution must not hold the CA store lock. After approval, the CA
re-locks and signs only if the same CSR is still pending.

`AutosignPolicyTimeout` / `-autosign-policy-timeout` defaults to `5s`.
Configuring a policy executable without autosign is invalid. The configured
policy executable path must be absolute. Startup validates that the configured
executable exists and is not a directory; later execution failures are policy
errors. Configuring a policy timeout without a policy executable is invalid.

## Consequences

- Automatic signing remains an explicit operator choice.
- Existing blanket autosign behavior stays unchanged unless a policy executable
  is configured.
- CMDB-backed approval can become true later: resubmitting the same pending CSR
  re-runs the policy.
- A slow or broken policy cannot block the CA store lock, and cannot make the
  enrolling agent's CSR submission fail after the CSR was stored.
- The policy API stays script-friendly and stable by exposing the CA's parsed
  view instead of asking scripts to parse CSRs independently.
