## 1. Policy Contract

- [x] 1.1 Add an internal policy input type and builder for versioned JSON with `certname`, typed SANs, decoded `extension_requests`, recognized decoded CSR extensions, and `request.source_ip`.
- [x] 1.2 Add tests for policy input JSON, including Puppet extension short names, dotted OIDs, SANs, omitted unknown non-critical extensions, and rejected unknown critical extensions.
- [x] 1.3 Add policy executable runner with stdin JSON, no argv, inherited env/cwd, `5s` default timeout, stderr cap, ignored stdout, and exit-status mapping.
- [x] 1.4 Add tests for approve, deny, timeout, execution error, non-0/1 exit, stderr truncation, and no stdout parsing.

## 2. CA Integration

- [x] 2.1 Extend `ca.Options` and `castore.Options` with `AutosignPolicyExecutable` and `AutosignPolicyTimeout`.
- [x] 2.2 Validate policy configuration during `Init`/`Open`: requires `AutosignAll`, rejects timeout without executable, requires absolute executable path, and rejects missing paths or directories.
- [x] 2.3 Pass direct TCP peer IP from the HTTP handler into CSR submission without trusting proxy headers.
- [x] 2.4 Update CSR submission to normalize policy input before storage, store the CSR, execute policy outside the store lock, then sign only if the same CSR is still pending.
- [x] 2.5 Add tests for approve signing, deny pending, policy error pending, invalid normalization not stored, idempotent resubmission rerunning policy, and race-safe same-CSR signing.

## 3. CLI And Docs

- [x] 3.1 Add `facts-ca-server` flags `-autosign-policy-executable` and `-autosign-policy-timeout`, wired to `ca.Options`.
- [x] 3.2 Update README known simplifications/usage to describe policy-gated autosign and remove the claim that policy executables are not implemented.
- [x] 3.3 Run `go test ./...` and any focused e2e check needed for autosign behavior.
