package castore

import (
	"crypto/x509"
	"errors"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/ncode/facts-ca/internal/capi"
	"github.com/ncode/facts-ca/internal/ppext"
	"github.com/ncode/facts-ca/pki"
)

func mustPool(t *testing.T, caPEM []byte) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		t.Fatal("could not build CA pool")
	}
	return pool
}

func verifyOpts(roots *x509.CertPool) x509.VerifyOptions {
	return x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}
}

func csrFor(t *testing.T, name string) []byte {
	t.Helper()
	key, err := pki.GenerateKey(2048) // small key keeps the test fast
	if err != nil {
		t.Fatal(err)
	}
	csr, err := pki.CreateCSR(key, name, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

func TestSignRevokeFlow(t *testing.T) {
	dir := t.TempDir()
	ca, err := Init(dir, "test-ca", 2048, Options{})
	if err != nil {
		t.Fatal(err)
	}

	// Submit without autosign -> pending request.
	signed, err := ca.SubmitCSR("node1", csrFor(t, "node1"))
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if signed {
		t.Fatal("should not autosign when AutosignAll is false")
	}
	if st, _ := ca.Status("node1"); st.State != capi.StateRequested {
		t.Fatalf("state = %q, want requested", st.State)
	}
	if _, err := ca.GetCert("node1"); err != ErrNotFound {
		t.Fatalf("GetCert before sign = %v, want ErrNotFound", err)
	}

	// Sign it.
	if err := ca.Sign("node1", pki.SignOpts{}); err != nil {
		t.Fatalf("sign: %v", err)
	}
	pemCert, err := ca.GetCert("node1")
	if err != nil {
		t.Fatalf("GetCert after sign: %v", err)
	}
	crt, err := pki.DecodeCert(pemCert)
	if err != nil {
		t.Fatal(err)
	}
	if crt.Subject.CommonName != "node1" {
		t.Fatalf("CN = %q", crt.Subject.CommonName)
	}
	// Issued cert must verify against the CA.
	roots := mustPool(t, ca.CertPEM())
	if _, err := crt.Verify(verifyOpts(roots)); err != nil {
		t.Fatalf("issued cert does not chain to CA: %v", err)
	}
	if st, _ := ca.Status("node1"); st.State != capi.StateSigned {
		t.Fatalf("state = %q, want signed", st.State)
	}
	// Request file should be consumed.
	if _, err := ca.GetCSR("node1"); err != ErrNotFound {
		t.Fatalf("CSR still present after signing: %v", err)
	}

	// Revoke -> appears in CRL and status flips.
	if err := ca.Revoke("node1"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if st, _ := ca.Status("node1"); st.State != capi.StateRevoked {
		t.Fatalf("state = %q, want revoked", st.State)
	}
	crl, err := ca.CRL()
	if err != nil {
		t.Fatal(err)
	}
	if len(ca.readRevokedLocked()) != 1 {
		t.Fatalf("expected 1 revoked entry; CRL=%d bytes", len(crl))
	}

	// Serial numbers must be unique and monotonic (CA=1, server skipped, node1>=2).
	signed2, err := ca.SubmitCSR("node2", csrFor(t, "node2"))
	if err != nil || signed2 {
		t.Fatalf("submit node2: signed=%v err=%v", signed2, err)
	}
	if err := ca.Sign("node2", pki.SignOpts{}); err != nil {
		t.Fatal(err)
	}
	c1, _ := ca.GetCert("node1")
	c2, _ := ca.GetCert("node2")
	x1, _ := pki.DecodeCert(c1)
	x2, _ := pki.DecodeCert(c2)
	if x1.SerialNumber.Cmp(x2.SerialNumber) == 0 {
		t.Fatal("serials collided")
	}
}

func TestAutosignAndMismatch(t *testing.T) {
	dir := t.TempDir()
	ca, err := Init(dir, "test-ca", 2048, Options{AutosignAll: true})
	if err != nil {
		t.Fatal(err)
	}
	signed, err := ca.SubmitCSR("auto", csrFor(t, "auto"))
	if err != nil {
		t.Fatal(err)
	}
	if !signed {
		t.Fatal("autosign should have signed immediately")
	}
	if _, err := ca.GetCert("auto"); err != nil {
		t.Fatalf("autosigned cert missing: %v", err)
	}

	// CN/certname mismatch must be rejected (anti-spoofing).
	if _, err := ca.SubmitCSR("claimed", csrFor(t, "different")); err == nil {
		t.Fatal("expected rejection when CSR CN != certname")
	}

	// Path traversal in certname must be rejected.
	if _, err := ca.SubmitCSR("../evil", csrFor(t, "../evil")); err == nil {
		t.Fatal("expected rejection of traversal certname")
	}
}

func TestExtensionsCopiedOnSign(t *testing.T) {
	dir := t.TempDir()
	ca, err := Init(dir, "test-ca", 2048, Options{AutosignAll: true})
	if err != nil {
		t.Fatal(err)
	}
	key, err := pki.GenerateKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	exts, err := ppext.BuildExtensions(map[string]string{
		"pp_role":          "web",
		"pp_authorization": "true",
		"1.2.3.4":          "not-a-puppet-oid",
	})
	if err != nil {
		t.Fatal(err)
	}
	csr, err := pki.CreateCSR(key, "ext-node", nil, exts)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ca.SubmitCSR("ext-node", csr); err != nil {
		t.Fatal(err)
	}
	pemCert, err := ca.GetCert("ext-node")
	if err != nil {
		t.Fatal(err)
	}
	crt, err := pki.DecodeCert(pemCert)
	if err != nil {
		t.Fatal(err)
	}
	got := ppext.Describe(crt.Extensions)
	if got["pp_role"] != "web" || got["pp_authorization"] != "true" {
		t.Fatalf("issued cert missing trusted-fact extensions: %v", got)
	}
	if _, bad := got["1.2.3.4"]; bad {
		t.Fatal("CA copied a non-puppet OID into the cert")
	}
	// And it should appear in certificate_status authorization_extensions.
	st, _ := ca.Status("ext-node")
	if st.AuthzExtensions["pp_authorization"] != "true" {
		t.Fatalf("authorization_extensions = %v", st.AuthzExtensions)
	}
}

func TestAltSANPolicyAndCSRConflict(t *testing.T) {
	key, err := pki.GenerateKey(2048)
	if err != nil {
		t.Fatal(err)
	}

	// AllowAltSAN defaults false: agent-requested SANs must be dropped.
	ca := mustInit(t, Options{AutosignAll: true})
	csr, _ := pki.CreateCSR(key, "san-node", []string{"evil.example.com"}, nil)
	if _, err := ca.SubmitCSR("san-node", csr); err != nil {
		t.Fatal(err)
	}
	crt := mustCert(t, ca, "san-node")
	if len(crt.DNSNames) != 0 {
		t.Fatalf("SANs should be dropped by default; got %v", crt.DNSNames)
	}

	// With AllowAltSAN on, the requested SAN is honored.
	ca2 := mustInit(t, Options{AutosignAll: true, AllowAltSAN: true})
	csr2, _ := pki.CreateCSR(key, "san2", []string{"ok.example.com"}, nil)
	if _, err := ca2.SubmitCSR("san2", csr2); err != nil {
		t.Fatal(err)
	}
	if got := mustCert(t, ca2, "san2").DNSNames; !slices.Contains(got, "ok.example.com") {
		t.Fatalf("SAN should be honored; got %v", got)
	}

	// Identical re-submission is idempotent; a different CSR for the same name conflicts.
	ca3 := mustInit(t, Options{})
	c1, _ := pki.CreateCSR(key, "dup", nil, nil)
	if _, err := ca3.SubmitCSR("dup", c1); err != nil {
		t.Fatal(err)
	}
	if _, err := ca3.SubmitCSR("dup", c1); err != nil {
		t.Fatalf("identical re-submit should be idempotent: %v", err)
	}
	key2, _ := pki.GenerateKey(2048)
	c2, _ := pki.CreateCSR(key2, "dup", nil, nil)
	if _, err := ca3.SubmitCSR("dup", c2); err == nil {
		t.Fatal("a different CSR for an existing pending name should be rejected")
	}
}

func TestIssuesCertificateForLongFQDN(t *testing.T) {
	name := strings.Repeat("a", 50) + "." + strings.Repeat("b", 50) + "." + strings.Repeat("c", 20) + ".example.test"
	if len(name) <= 128 {
		t.Fatalf("test FQDN length = %d, want >128", len(name))
	}
	ca := mustInit(t, Options{AutosignAll: true, AllowAltSAN: true})
	key, err := pki.GenerateKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := pki.CreateCSR(key, name, []string{name}, nil)
	if err != nil {
		t.Fatal(err)
	}
	signed, err := ca.SubmitCSR(name, csr)
	if err != nil {
		t.Fatalf("SubmitCSR long FQDN: %v", err)
	}
	if !signed {
		t.Fatal("long FQDN CSR was not autosigned")
	}
	crt := mustCert(t, ca, name)
	if crt.Subject.CommonName != name || !slices.Contains(crt.DNSNames, name) {
		t.Fatalf("issued cert CN/SAN = %q/%v, want %q", crt.Subject.CommonName, crt.DNSNames, name)
	}
}

func TestOpenCleanAndServerTLSCert(t *testing.T) {
	dir := t.TempDir()
	if _, err := Init(dir, "test-ca", 2048, Options{}); err != nil {
		t.Fatal(err)
	}
	ca, err := Open(dir, Options{TTL: time.Hour})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if ca.Cert() == nil || ca.Key() == nil {
		t.Fatal("Open did not load CA certificate and key")
	}

	ca.SetAutosignAll(true)
	signed, err := ca.SubmitCSR("auto-open", csrFor(t, "auto-open"))
	if err != nil {
		t.Fatalf("autosign submit after Open: %v", err)
	}
	if !signed {
		t.Fatal("SetAutosignAll(true) did not autosign the CSR")
	}
	statuses, err := ca.Statuses()
	if err != nil {
		t.Fatal(err)
	}
	if len(statuses) != 1 || statuses[0].Name != "auto-open" || statuses[0].State != capi.StateSigned {
		t.Fatalf("Statuses after autosign = %+v", statuses)
	}

	leaf, err := ca.ServerTLSCert([]string{"127.0.0.1", "ca.local"})
	if err != nil {
		t.Fatalf("ServerTLSCert: %v", err)
	}
	if len(leaf.Certificate) != 2 || leaf.Leaf == nil {
		t.Fatalf("server TLS chain = %#v", leaf.Certificate)
	}
	if !slices.Contains(leaf.Leaf.DNSNames, "ca.local") {
		t.Fatalf("server DNSNames = %v, want ca.local", leaf.Leaf.DNSNames)
	}
	if !slices.ContainsFunc(leaf.Leaf.IPAddresses, func(ip net.IP) bool { return ip.String() == "127.0.0.1" }) {
		t.Fatalf("server IPAddresses = %v, want 127.0.0.1", leaf.Leaf.IPAddresses)
	}
	if _, err := leaf.Leaf.Verify(x509.VerifyOptions{Roots: mustPool(t, ca.CertPEM()), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Fatalf("server leaf does not chain to CA: %v", err)
	}
	again, err := ca.ServerTLSCert([]string{"127.0.0.1", "ca.local"})
	if err != nil {
		t.Fatal(err)
	}
	if again.Leaf.SerialNumber.Cmp(leaf.Leaf.SerialNumber) != 0 {
		t.Fatal("ServerTLSCert minted a new cert instead of reusing the persisted one")
	}

	ca.SetAutosignAll(false)
	if _, err := ca.SubmitCSR("pending-clean", csrFor(t, "pending-clean")); err != nil {
		t.Fatalf("submit pending-clean: %v", err)
	}
	if err := ca.Clean("pending-clean"); err != nil {
		t.Fatalf("Clean pending CSR: %v", err)
	}
	if _, err := ca.Status("pending-clean"); err != ErrNotFound {
		t.Fatalf("Status after Clean = %v, want ErrNotFound", err)
	}
	if err := ca.Clean("missing"); err != ErrNotFound {
		t.Fatalf("Clean missing = %v, want ErrNotFound", err)
	}
}

func TestStatusesSortAndReportIPSANs(t *testing.T) {
	ca := mustInit(t, Options{AutosignAll: true, AllowAltSAN: true})
	key, err := pki.GenerateKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"z-node", "a-node"} {
		csr, err := pki.CreateCSR(key, name, []string{"127.0.0.1"}, nil)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ca.SubmitCSR(name, csr); err != nil {
			t.Fatal(err)
		}
	}
	list, err := ca.Statuses()
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != 2 || list[0].Name != "a-node" || list[1].Name != "z-node" {
		t.Fatalf("Statuses order = %+v", list)
	}
	if !slices.Contains(list[0].DNSAltN, "IP:127.0.0.1") {
		t.Fatalf("DNSAltN = %v, want IP SAN", list[0].DNSAltN)
	}

	if err := os.WriteFile(filepath.Join(ca.dir, "ca_crl.pem"), []byte("bad crl"), 0o644); err != nil {
		t.Fatal(err)
	}
	if st, err := ca.Status("a-node"); err != nil || st.State != capi.StateSigned {
		t.Fatalf("Status with corrupt CRL = %+v, %v", st, err)
	}
}

func TestStoreErrorsAndDeleteCSR(t *testing.T) {
	ca := mustInit(t, Options{})
	if _, err := ca.GetCert("ca"); err != nil {
		t.Fatalf("GetCert(ca): %v", err)
	}
	for _, fn := range []struct {
		name string
		run  func() error
	}{
		{"GetCSR invalid", func() error { _, err := ca.GetCSR("../bad"); return err }},
		{"GetCert invalid", func() error { _, err := ca.GetCert("../bad"); return err }},
		{"Sign invalid", func() error { return ca.Sign("../bad", pki.SignOpts{}) }},
		{"Revoke invalid", func() error { return ca.Revoke("../bad") }},
		{"Status invalid", func() error { _, err := ca.Status("../bad"); return err }},
		{"Clean invalid", func() error { return ca.Clean("../bad") }},
		{"DeleteCSR invalid", func() error { return ca.DeleteCSR("../bad") }},
	} {
		if err := fn.run(); !errors.Is(err, ErrNotFound) {
			t.Fatalf("%s = %v, want ErrNotFound", fn.name, err)
		}
	}

	if _, err := ca.SubmitCSR("pending", csrFor(t, "pending")); err != nil {
		t.Fatal(err)
	}
	if err := ca.DeleteCSR("pending"); err != nil {
		t.Fatalf("DeleteCSR pending: %v", err)
	}
	if _, err := ca.GetCSR("pending"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetCSR after delete = %v, want ErrNotFound", err)
	}
	if err := ca.DeleteCSR("pending"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("DeleteCSR missing = %v, want ErrNotFound", err)
	}

	if _, err := ca.SubmitCSR("dup-signed", csrFor(t, "dup-signed")); err != nil {
		t.Fatal(err)
	}
	if err := ca.Sign("dup-signed", pki.SignOpts{}); err != nil {
		t.Fatal(err)
	}
	if _, err := ca.SubmitCSR("dup-signed", csrFor(t, "dup-signed")); err == nil || !strings.Contains(err.Error(), "already signed") {
		t.Fatalf("SubmitCSR for signed cert = %v, want already signed", err)
	}
	if err := ca.Revoke("dup-signed"); err != nil {
		t.Fatal(err)
	}
	if err := ca.Revoke("dup-signed"); err != nil {
		t.Fatalf("second Revoke should be idempotent: %v", err)
	}

	if _, err := ca.ServerTLSCert(nil); err == nil {
		t.Fatal("ServerTLSCert with no names succeeded")
	}
}

func TestOpenAndSerialCorruptionErrors(t *testing.T) {
	dir := t.TempDir()
	if _, err := Init(dir, "test-ca", 2048, Options{}); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(filepath.Join(dir, "missing"), Options{}); err == nil {
		t.Fatal("Open missing dir succeeded")
	}
	if err := os.WriteFile(filepath.Join(dir, "ca_crt.pem"), []byte("not pem"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, Options{}); err == nil {
		t.Fatal("Open with corrupt CA cert succeeded")
	}

	dir = t.TempDir()
	ca, err := Init(dir, "test-ca", 2048, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ca.SubmitCSR("serial-bad", csrFor(t, "serial-bad")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "serial"), []byte("not-hex\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ca.Sign("serial-bad", pki.SignOpts{}); err == nil || !strings.Contains(err.Error(), "corrupt serial") {
		t.Fatalf("Sign with corrupt serial = %v, want corrupt serial", err)
	}
}

func mustInit(t *testing.T, opts Options) *CA {
	t.Helper()
	ca, err := Init(t.TempDir(), "test-ca", 2048, opts)
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

func mustCert(t *testing.T, ca *CA, name string) *x509.Certificate {
	t.Helper()
	b, err := ca.GetCert(name)
	if err != nil {
		t.Fatal(err)
	}
	crt, err := pki.DecodeCert(b)
	if err != nil {
		t.Fatal(err)
	}
	return crt
}

func TestValidName(t *testing.T) {
	ok := []string{"host", "host.example.com", "a1.b2-c3_d4"}
	bad := []string{"", "../x", "a/b", "UPPER", ".lead", "trail.", "a..b"}
	for _, n := range ok {
		if !ValidName(n) {
			t.Errorf("ValidName(%q) = false, want true", n)
		}
	}
	for _, n := range bad {
		if ValidName(n) {
			t.Errorf("ValidName(%q) = true, want false", n)
		}
	}
}
