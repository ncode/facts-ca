package castore

import (
	"crypto/x509"
	"slices"
	"testing"

	"github.com/ncode/facts-ca/internal/capi"
	"github.com/ncode/facts-ca/internal/pki"
	"github.com/ncode/facts-ca/internal/ppext"
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
