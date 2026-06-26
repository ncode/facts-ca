# Facts CA (Go port of the Puppet CA)

## Unreleased

### Added

- `facts-ca-server`: a Go port of the Puppet CA service that speaks the Puppet
  CA v1 HTTP API over mTLS, so real Puppet agents (and `facts-ca-cli`) can
  bootstrap certificates against it. Implements `certificate/:name` (including
  `ca`), `certificate_request/:name` (PUT/GET/DELETE),
  `certificate_revocation_list/ca`, and the admin `certificate_status[es]`
  endpoints, with `-init`, offline `list`/`sign`/`revoke`/`clean` subcommands,
  optional `-autosign`, and `-allow-dns-alt-names` mirroring puppetserver's
  `allow-subject-alt-names`.
- `facts-ca-cli`: a Go port of the Puppet agent's CA bootstrap. It trusts the CA
  cert on first use, generates an RSA-4096/SHA-256 key and CSR, submits it,
  polls until signed (`--waitforcert`, `--onetime`), and writes a
  Puppet-compatible `ssldir`. Adds `mtls` for issued-cert requests and a
  `ca list|sign|revoke` admin client over mTLS.
- Puppet trusted-fact extensions: `extension_requests` in the registered OID arc
  `1.3.6.1.4.1.34380.1.*` are embedded by the CLI (via repeatable `--ext` short
  names/OIDs or a Puppet `csr_attributes.yaml`) and copied into the issued cert
  by the server, which drops anything outside the arc as puppetserver does.
  Values are encoded as DER `UTF8String`, matching Puppet.
- On-disk compatibility with Puppet: the agent `ssldir` (`private_keys/`,
  `public_keys/`, `certs/`, `certificate_requests/`, `crl.pem`) and the server
  `cadir` (`ca_crt.pem`, `ca_key.pem`, `ca_crl.pem`, `serial`, `inventory.txt`,
  `signed/`, `requests/`), with PKCS#1 private keys and PKIX public keys that
  byte-match OpenSSL/Puppet output.
- `./e2e.sh` proves the server and CLI interoperate over the wire (bootstrap,
  extension copying, mTLS admin and data paths, chain verification), and
  `./interop.sh` plus `docker-compose.yml` prove wire compatibility against a
  real `puppet/puppetserver` container.
- README "Known simplifications" documenting the deliberate deviations from
  puppetserver: all-or-nothing `-autosign` (no `autosign.conf` globs or policy
  executables), unembedded `custom_attributes`, the unlocked `serial` file, and
  "any CA-signed client cert" admin authorization.
