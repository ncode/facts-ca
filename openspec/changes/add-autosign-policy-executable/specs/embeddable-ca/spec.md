## MODIFIED Requirements

### Requirement: Autosign and SAN policy options

`Options.AutosignAll` SHALL cause every valid incoming CSR to be signed
immediately when no policy executable is configured. `Options.AllowAltSAN`
(default false, matching puppetserver) SHALL control whether agent-requested
subjectAltNames are honored. When `Options.AutosignPolicyExecutable` is
configured with `AutosignAll`, the CA SHALL run the configured executable to
decide whether a stored CSR is automatically signed.

#### Scenario: SANs are dropped by default

- **WHEN** `AllowAltSAN` is false and an agent CSR requests a subjectAltName
- **THEN** the issued certificate omits that SAN

#### Scenario: Policy approves autosign

- **WHEN** `AutosignAll` is true, `AutosignPolicyExecutable` is configured, and
  the policy exits `0` for a valid CSR
- **THEN** the CSR is stored and automatically signed

#### Scenario: Policy denies autosign

- **WHEN** `AutosignAll` is true, `AutosignPolicyExecutable` is configured, and
  the policy exits `1` for a valid CSR
- **THEN** the CSR remains in the requested state and is not signed

#### Scenario: Policy error leaves CSR pending

- **WHEN** `AutosignAll` is true, `AutosignPolicyExecutable` is configured, and
  the policy times out, cannot execute, or exits with any status other than `0`
  or `1`
- **THEN** the CSR remains in the requested state and is not signed

#### Scenario: Policy input is normalized before storage

- **WHEN** policy autosign is configured and a CSR cannot be converted into the
  versioned policy JSON input
- **THEN** the CSR is rejected and is not stored

#### Scenario: Policy receives normalized request context

- **WHEN** policy autosign evaluates a CSR submitted over HTTP
- **THEN** the policy input includes `version: 1`, the validated `certname`,
  typed DNS/IP subject alternative names, decoded Puppet `extension_requests`,
  recognized decoded CSR extensions, and `request.source_ip` from the direct TCP
  peer

#### Scenario: Resubmitting the same pending CSR reruns policy

- **WHEN** a CSR is pending after a deny or policy error and the same CSR is
  submitted again
- **THEN** the policy executable is run again and the CSR is signed if the later
  policy result approves it

#### Scenario: Invalid policy configuration is rejected

- **WHEN** a policy executable is configured without `AutosignAll`, a policy
  timeout is configured without a policy executable, the policy executable path
  is relative, or the configured executable does not exist or is a directory
- **THEN** opening or initializing the CA returns an error
