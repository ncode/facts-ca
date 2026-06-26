// Package capi defines the wire contract of the Puppet CA v1 HTTP API that
// both facts-ca-server and facts-ca-cli speak. Paths, content types and JSON
// shapes mirror puppetserver so a real Puppet agent can talk to our server and
// our client can talk to a real puppetserver.
package capi

import (
	"encoding/json"
	"regexp"
	"strings"
)

// Base is the URL prefix for every CA endpoint.
const Base = "/puppet-ca/v1"

// certnameRE constrains a Puppet-style certname to safe, single-segment names.
var certnameRE = regexp.MustCompile(`^[a-z0-9]([a-z0-9._-]*[a-z0-9])?$`)

// ValidCertname reports whether name is a safe certname: no path separators,
// no traversal, lowercase Puppet/hostname charset. Used on both the client
// (ssldir paths) and server (cadir paths).
func ValidCertname(name string) bool {
	return name != "" && len(name) <= 255 && certnameRE.MatchString(name) && !strings.Contains(name, "..")
}

// PEMContentType is what puppetserver returns and the agent sends for
// certificates, CSRs and CRLs. We emit this and accept anything on input.
const PEMContentType = "text/plain"

// Certificate states reported by the certificate_status API.
const (
	StateRequested = "requested" // CSR on file, not yet signed
	StateSigned    = "signed"
	StateRevoked   = "revoked"
)

// CertStatus is the JSON body of GET /certificate_status/:name and each element
// of GET /certificate_statuses/:any. Field names match puppetserver exactly.
type CertStatus struct {
	Name         string            `json:"name"`
	State        string            `json:"state"`
	Fingerprint  string            `json:"fingerprint"`
	Fingerprints map[string]string `json:"fingerprints"`
	SubjectAltN  []string          `json:"subject_alt_names"`
	DNSAltN      []string          `json:"dns_alt_names"`
	// SerialNumber is a json.Number so arbitrary-precision X.509 serials (which
	// can exceed int64) round-trip with a real puppetserver.
	SerialNumber    json.Number       `json:"serial_number,omitempty"`
	NotBefore       string            `json:"not_before,omitempty"`
	NotAfter        string            `json:"not_after,omitempty"`
	AuthzExtensions map[string]string `json:"authorization_extensions"`
}

// DesiredState is the JSON body of PUT /certificate_status/:name. desired_state
// is "signed" or "revoked"; the optional fields override signing defaults.
type DesiredState struct {
	DesiredState string   `json:"desired_state"`
	DNSAltNames  []string `json:"dns_alt_names,omitempty"`
	CertTTL      string   `json:"cert_ttl,omitempty"`
}
