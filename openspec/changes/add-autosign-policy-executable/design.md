## Context

The CA store currently has one autosign mode: `AutosignAll`, which signs every
valid incoming CSR after writing it to the cadir. That mode is useful for tests
and lab deployments, but it lets requesters self-assert Puppet trusted-fact
extensions. The new mode keeps autosign explicit while allowing an operator
script to approve or deny each CSR using a CMDB or similar source of truth.

## Goals / Non-Goals

**Goals:**

- Keep blanket autosign behavior unchanged unless a policy executable is
  configured.
- Give policy scripts a stable, versioned JSON input built from the CA's parsed
  CSR view and direct TCP request context.
- Leave denied and policy-error CSRs pending for manual signing or later
  resubmission.
- Avoid holding the CA store lock while running an external process.

**Non-Goals:**

- No `autosign.conf` glob support.
- No policy response body or JSON output protocol.
- No raw CSR PEM or raw DER extension bytes in the policy contract.
- No trusted proxy or PROXY protocol support in this change.
- No persisted denial/error state beyond the existing requested status.

## Decisions

Use `-autosign` as the required enablement switch. `AutosignPolicyExecutable`
only narrows automatic signing; configuring a policy without autosign is invalid.
This avoids a second implicit way to enable certificate issuance.

Use JSON on stdin and exit status as output. JSON handles nested request data and
extension values without shell quoting. Exit status keeps policy scripts simple:
`0` approves, `1` denies, any other outcome is a policy error.

Normalize policy input before storing, execute policy after storing. A CSR that
cannot produce safe policy JSON is rejected and not written. Once normalization
succeeds, the CSR is written before executing the policy so denial/error leaves a
durable pending request.

Run policy execution outside the CA store lock. After approval, re-lock and sign
only if the same CSR is still pending. This prevents slow CMDB calls from
blocking unrelated CA operations while preserving the "approved this exact CSR"
invariant.

Expose decoded values only. Puppet extension request values are strings, known
structured X.509 extensions use typed JSON values, unknown non-critical
extensions are omitted, and unknown critical extensions reject policy autosign.
This gives scripts the CA's authoritative parsed view without asking them to
parse CSRs independently.

Validate configuration at startup/open/init. Policy executable paths must be
absolute, exist, and not be directories. Ownership and mode checks are left to
the operating system because the project targets multiple platforms.

## Risks / Trade-offs

- Policy scripts may need credentials from the process environment -> the
  policy process inherits the server environment, and operators remain
  responsible for securing service configuration.
- A policy executable can become unavailable after startup -> treat runtime
  execution failures as policy errors and leave CSRs pending.
- Source IP is only the direct TCP peer -> deployments behind proxies will see
  the proxy address until trusted PROXY protocol support is added.
- The first JSON version may need future fields -> include `version: 1`; additive
  fields do not require a version bump.
