// Package ppext implements Puppet's registered certificate extension OIDs (the
// "extended attributes" / trusted facts in the 1.3.6.1.4.1.34380.1.* arc) so
// facts-ca-cli can embed extension_requests in a CSR and facts-ca-server can
// copy the allowed ones into the issued certificate — matching what a Puppet
// agent's csr_attributes.yaml does against a real puppetserver.
//
// Arcs (RFC-style):
//
//	ppRegCertExt  = 1.3.6.1.4.1.34380.1.1.*  registered (pp_uuid, pp_role, ...)
//	ppPrivCertExt = 1.3.6.1.4.1.34380.1.2.*  private / user-defined
//	ppAuthCertExt = 1.3.6.1.4.1.34380.1.3.*  authorization (pp_authorization, pp_auth_role)
package ppext

import (
	"encoding/asn1"
	"fmt"
	"strconv"
	"strings"
)

// base is 1.3.6.1.4.1.34380.1 — the Puppet Labs cert-extension namespace.
var base = []int{1, 3, 6, 1, 4, 1, 34380, 1}

func reg(n int) asn1.ObjectIdentifier  { return oid(1, n) }
func auth(n int) asn1.ObjectIdentifier { return oid(3, n) }
func oid(sub, n int) asn1.ObjectIdentifier {
	o := make(asn1.ObjectIdentifier, 0, len(base)+2)
	o = append(o, base...)
	return append(o, sub, n)
}

// names maps Puppet short names to OIDs and back. The registered set (.1.1.*)
// and the auth set (.1.3.*) both have well-known short names.
var names = map[string]asn1.ObjectIdentifier{
	"pp_uuid":             reg(1),
	"pp_instance_id":      reg(2),
	"pp_image_name":       reg(3),
	"pp_preshared_key":    reg(4),
	"pp_cost_center":      reg(5),
	"pp_product":          reg(6),
	"pp_project":          reg(7),
	"pp_application":      reg(8),
	"pp_service":          reg(9),
	"pp_employee":         reg(10),
	"pp_created_by":       reg(11),
	"pp_environment":      reg(12),
	"pp_role":             reg(13),
	"pp_software_version": reg(14),
	"pp_department":       reg(15),
	"pp_cluster":          reg(16),
	"pp_provisioner":      reg(17),
	"pp_region":           reg(18),
	"pp_datacenter":       reg(19),
	"pp_zone":             reg(20),
	"pp_network":          reg(21),
	"pp_securitypolicy":   reg(22),
	"pp_cloudplatform":    reg(23),
	"pp_apptier":          reg(24),
	"pp_hostname":         reg(25),
	"pp_authorization":    auth(1),
	"pp_auth_role":        auth(13),
}

// oidToName is the reverse index, built once.
var oidToName = func() map[string]string {
	m := make(map[string]string, len(names))
	for n, o := range names {
		m[o.String()] = n
	}
	return m
}()

// ResolveOID turns a Puppet short name ("pp_role") or a dotted OID string
// ("1.3.6.1.4.1.34380.1.2.1") into an OID.
func ResolveOID(nameOrOID string) (asn1.ObjectIdentifier, error) {
	if o, ok := names[nameOrOID]; ok {
		return o, nil
	}
	parts := strings.Split(nameOrOID, ".")
	if len(parts) < 3 {
		return nil, fmt.Errorf("unknown extension name or OID %q", nameOrOID)
	}
	o := make(asn1.ObjectIdentifier, len(parts))
	for i, p := range parts {
		v, err := strconv.Atoi(p)
		if err != nil || v < 0 {
			return nil, fmt.Errorf("invalid OID %q: bad arc %q", nameOrOID, p)
		}
		o[i] = v
	}
	if o[0] > 2 || (o[0] < 2 && o[1] > 39) { // ASN.1 leading-arc constraints
		return nil, fmt.Errorf("invalid OID %q: leading arcs out of range", nameOrOID)
	}
	return o, nil
}

// NameFor returns the Puppet short name for an OID, or its dotted string.
func NameFor(o asn1.ObjectIdentifier) string {
	if n, ok := oidToName[o.String()]; ok {
		return n
	}
	return o.String()
}

// encodeValue DER-encodes an extension value as a UTF8String, which is what
// Puppet uses for extension_requests (so values round-trip identically).
func encodeValue(v string) ([]byte, error) {
	return asn1.Marshal(asn1.RawValue{
		Class:      asn1.ClassUniversal,
		Tag:        asn1.TagUTF8String,
		IsCompound: false,
		Bytes:      []byte(v),
	})
}

// DecodeValue extracts the string from a Puppet extension value (UTF8String or
// PrintableString). Falls back to the raw bytes if it is not a TLV string.
func DecodeValue(der []byte) string {
	var raw asn1.RawValue
	if rest, err := asn1.Unmarshal(der, &raw); err == nil && len(rest) == 0 &&
		raw.Class == asn1.ClassUniversal &&
		(raw.Tag == asn1.TagUTF8String || raw.Tag == asn1.TagPrintableString) {
		return string(raw.Bytes) // valid (possibly empty) string value
	}
	return string(der)
}

// IsPuppetOID reports whether o lives under the Puppet extension arc, i.e. is
// one the CA is willing to copy from a CSR into the issued cert.
func IsPuppetOID(o asn1.ObjectIdentifier) bool {
	if len(o) < len(base) {
		return false
	}
	for i, v := range base {
		if o[i] != v {
			return false
		}
	}
	return true
}

// IsAuthOID reports whether o is in the authorization subtree (.1.3.*), which
// puppetserver surfaces as authorization_extensions.
func IsAuthOID(o asn1.ObjectIdentifier) bool {
	return IsPuppetOID(o) && len(o) > len(base) && o[len(base)] == 3
}
