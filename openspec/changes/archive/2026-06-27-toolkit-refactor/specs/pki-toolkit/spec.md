## ADDED Requirements

### Requirement: Public X.509 primitives

The `pki` package SHALL be public and provide standalone X.509 tooling: RSA key
generation, CSR creation (with extension requests), CA and leaf certificate
signing, CRL generation, certificate fingerprints, and PEM encode/decode.

#### Scenario: Generate a key, CSR, and signed leaf

- **WHEN** a caller generates a key, builds a CSR, creates a CA, and signs the CSR
  using only the `pki` package
- **THEN** the resulting leaf certificate verifies against the CA certificate

### Requirement: Encodings match OpenSSL/Puppet

PEM encodings SHALL byte-match what OpenSSL/Puppet produce: RSA private keys in
PKCS#1 (`RSA PRIVATE KEY`), public keys in PKIX (`PUBLIC KEY`), and certificates,
CSRs and CRLs in their standard PEM blocks.

#### Scenario: Private key round-trips as PKCS#1

- **WHEN** a generated RSA key is encoded and re-decoded with `pki`
- **THEN** the PEM block type is `RSA PRIVATE KEY` and the key is recovered intact
