package ppext

import (
	"crypto/x509/pkix"
	"os"
	"path/filepath"
	"testing"
)

func TestResolveAndName(t *testing.T) {
	o, err := ResolveOID("pp_role")
	if err != nil {
		t.Fatal(err)
	}
	if got := o.String(); got != "1.3.6.1.4.1.34380.1.1.13" {
		t.Fatalf("pp_role OID = %s", got)
	}
	if NameFor(o) != "pp_role" {
		t.Fatalf("NameFor = %s", NameFor(o))
	}
	// Dotted private OID resolves and round-trips as its dotted string.
	priv, err := ResolveOID("1.3.6.1.4.1.34380.1.2.99")
	if err != nil {
		t.Fatal(err)
	}
	if NameFor(priv) != "1.3.6.1.4.1.34380.1.2.99" {
		t.Fatalf("private NameFor = %s", NameFor(priv))
	}
	if _, err := ResolveOID("not_a_thing"); err == nil {
		t.Fatal("expected error for unknown name")
	}
}

func TestValueRoundTrip(t *testing.T) {
	der, err := encodeValue("web-server")
	if err != nil {
		t.Fatal(err)
	}
	if der[0] != 0x0c { // UTF8String tag, matching Puppet
		t.Fatalf("value tag = %#x, want 0x0c (UTF8String)", der[0])
	}
	if got := DecodeValue(der); got != "web-server" {
		t.Fatalf("DecodeValue = %q", got)
	}
}

func TestOIDClassification(t *testing.T) {
	reg13, _ := ResolveOID("pp_role")
	auth1, _ := ResolveOID("pp_authorization")
	other := pkix.Extension{Id: []int{1, 2, 3, 4}}.Id
	if !IsPuppetOID(reg13) || !IsPuppetOID(auth1) {
		t.Fatal("puppet OIDs misclassified")
	}
	if IsPuppetOID(other) {
		t.Fatal("non-puppet OID accepted")
	}
	if !IsAuthOID(auth1) {
		t.Fatal("auth OID not detected")
	}
	if IsAuthOID(reg13) {
		t.Fatal("registered OID wrongly flagged as auth")
	}
}

func TestBuildAndFilter(t *testing.T) {
	exts, err := BuildExtensions(map[string]string{
		"pp_role":          "web",
		"1.2.3.4":          "should-be-dropped-by-CA",
		"pp_authorization": "true",
	})
	if err != nil {
		t.Fatal(err)
	}
	allowed := AllowedFromCSR(exts)
	got := Describe(allowed)
	if got["pp_role"] != "web" || got["pp_authorization"] != "true" {
		t.Fatalf("describe = %v", got)
	}
	if _, bad := got["1.2.3.4"]; bad {
		t.Fatal("non-puppet OID survived CA filter")
	}
	if auth := AuthExtensions(allowed); auth["pp_authorization"] != "true" || len(auth) != 1 {
		t.Fatalf("auth extensions = %v", auth)
	}
	if _, err := BuildExtensions(map[string]string{
		"pp_role":                  "web",
		"1.3.6.1.4.1.34380.1.1.13": "same oid",
	}); err == nil {
		t.Fatal("BuildExtensions accepted duplicate OIDs")
	}
}

func TestParseCSRAttributes(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "csr_attributes.yaml")
	content := `# sample
custom_attributes:
  1.2.840.113549.1.9.7: "mypassword"
extension_requests:
  pp_role: web
  pp_uuid: "ED803750-E3C7-44F5-BB08-41A04433FE2E"
`
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	ext, custom, err := ParseCSRAttributes(path)
	if err != nil {
		t.Fatal(err)
	}
	if ext["pp_role"] != "web" || ext["pp_uuid"] != "ED803750-E3C7-44F5-BB08-41A04433FE2E" {
		t.Fatalf("extension_requests = %v", ext)
	}
	if custom["1.2.840.113549.1.9.7"] != "mypassword" {
		t.Fatalf("custom_attributes = %v", custom)
	}
}
