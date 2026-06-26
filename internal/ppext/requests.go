package ppext

import (
	"crypto/x509/pkix"
	"fmt"
	"os"
	"sort"
	"strings"
)

// BuildExtensions turns a name/OID -> value map into CSR extension requests with
// Puppet's UTF8String encoding. Keys may be short names ("pp_role") or dotted
// OIDs. Output is sorted for deterministic CSRs.
func BuildExtensions(m map[string]string) ([]pkix.Extension, error) {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]pkix.Extension, 0, len(m))
	seen := map[string]string{}
	for _, k := range keys {
		oid, err := ResolveOID(k)
		if err != nil {
			return nil, err
		}
		if prev, dup := seen[oid.String()]; dup {
			return nil, fmt.Errorf("duplicate extension OID %s from %q and %q", oid, prev, k)
		}
		seen[oid.String()] = k
		val, err := encodeValue(m[k])
		if err != nil {
			return nil, err
		}
		out = append(out, pkix.Extension{Id: oid, Value: val})
	}
	return out, nil
}

// AllowedFromCSR returns only those CSR extensions the CA will copy into the
// issued cert: the ones in the Puppet extension arc. This mirrors puppetserver,
// which copies the registered/private/auth namespaces and ignores the rest.
func AllowedFromCSR(exts []pkix.Extension) []pkix.Extension {
	var out []pkix.Extension
	for _, e := range exts {
		if IsPuppetOID(e.Id) {
			out = append(out, pkix.Extension{Id: e.Id, Value: e.Value})
		}
	}
	return out
}

// Describe decodes a set of extensions into a name->value map for display.
func Describe(exts []pkix.Extension) map[string]string {
	out := map[string]string{}
	for _, e := range exts {
		if IsPuppetOID(e.Id) {
			out[NameFor(e.Id)] = DecodeValue(e.Value)
		}
	}
	return out
}

// AuthExtensions decodes only the authorization subtree (.1.3.*), the set
// puppetserver reports as authorization_extensions in certificate_status.
func AuthExtensions(exts []pkix.Extension) map[string]string {
	out := map[string]string{}
	for _, e := range exts {
		if IsAuthOID(e.Id) {
			out[NameFor(e.Id)] = DecodeValue(e.Value)
		}
	}
	return out
}

// ParseCSRAttributes reads a Puppet csr_attributes.yaml and returns its
// extension_requests and custom_attributes sections. It is a purpose-built
// reader for that file's flat two-section shape, not a general YAML parser.
//
// handles `key: value`, comments and quotes only — enough for
// csr_attributes.yaml; swap in a YAML lib if nested structures ever appear.
func ParseCSRAttributes(path string) (extReq, customAttr map[string]string, err error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	extReq, customAttr = map[string]string{}, map[string]string{}
	var cur map[string]string
	for raw := range strings.SplitSeq(string(b), "\n") {
		line := stripComment(raw)
		if strings.TrimSpace(line) == "" {
			continue
		}
		indented := line[0] == ' ' || line[0] == '\t'
		switch strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(line), ":")) {
		case "extension_requests":
			if !indented {
				cur = extReq
				continue
			}
		case "custom_attributes":
			if !indented {
				cur = customAttr
				continue
			}
		}
		k, v, ok := strings.Cut(line, ":")
		if !ok || cur == nil {
			continue
		}
		cur[strings.TrimSpace(k)] = unquote(strings.TrimSpace(v))
	}
	return extReq, customAttr, nil
}

// stripComment removes a trailing `#` comment but ignores `#` inside quotes, so
// values like `pp_role: "web#blue"` survive.
func stripComment(line string) string {
	var q byte
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case q != 0:
			if c == q {
				q = 0
			}
		case c == '"' || c == '\'':
			q = c
		case c == '#':
			return line[:i]
		}
	}
	return line
}

func unquote(s string) string {
	if len(s) >= 2 && (s[0] == '"' || s[0] == '\'') && s[len(s)-1] == s[0] {
		return s[1 : len(s)-1]
	}
	return s
}
