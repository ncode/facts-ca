package pki

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net"
	"slices"
	"strings"
	"testing"
	"time"
)

// TestStandaloneChain proves the pki package alone takes a key→CSR→CA→leaf and
// the leaf verifies against the CA, with no other facts-ca package involved
// (pki-toolkit spec: "Generate a key, CSR, and signed leaf").
func TestStandaloneChain(t *testing.T) {
	caKey, caCrt, err := CreateCA("standalone", 2048, 0)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := GenerateKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM, err := CreateCSR(leafKey, "leaf.example", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := DecodeCSR(csrPEM)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := SignCSR(csr, caCrt, caKey, SignOpts{})
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(caCrt)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("leaf does not chain to CA: %v", err)
	}
	if leaf.Subject.CommonName != "leaf.example" {
		t.Fatalf("CN = %q", leaf.Subject.CommonName)
	}
}

// TestPrivateKeyPKCS1RoundTrip proves the OpenSSL/Puppet-matching encoding:
// RSA keys are PKCS#1 ("RSA PRIVATE KEY") and survive a round-trip.
func TestPrivateKeyPKCS1RoundTrip(t *testing.T) {
	key, err := GenerateKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	enc := EncodePrivateKey(key)
	blk, _ := pem.Decode(enc)
	if blk == nil || blk.Type != "RSA PRIVATE KEY" {
		t.Fatalf("PEM block type = %v, want RSA PRIVATE KEY", blk)
	}
	got, err := DecodePrivateKey(enc)
	if err != nil {
		t.Fatal(err)
	}
	if got.N.Cmp(key.N) != 0 || got.E != key.E {
		t.Fatal("decoded key does not match original")
	}
}

func TestPEMDecodersRejectBadInputAndAcceptRSAPKCS8(t *testing.T) {
	key, err := GenerateKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodePrivateKey(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
	if err != nil {
		t.Fatalf("DecodePrivateKey PKCS#8 RSA: %v", err)
	}
	if got.N.Cmp(key.N) != 0 || got.E != key.E {
		t.Fatal("decoded PKCS#8 key does not match original")
	}

	for name, fn := range map[string]func([]byte) error{
		"private key": func(b []byte) error { _, err := DecodePrivateKey(b); return err },
		"cert":        func(b []byte) error { _, err := DecodeCert(b); return err },
		"csr":         func(b []byte) error { _, err := DecodeCSR(b); return err },
	} {
		if err := fn([]byte("not pem")); err == nil {
			t.Fatalf("%s decoder accepted non-PEM input", name)
		}
	}

	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edDER, err := x509.MarshalPKCS8PrivateKey(edKey)
	if err != nil {
		t.Fatal(err)
	}
	_, err = DecodePrivateKey(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: edDER}))
	if err == nil || !strings.Contains(err.Error(), "not RSA") {
		t.Fatalf("DecodePrivateKey Ed25519 error = %v, want not RSA", err)
	}
}

func TestSignCSRClampsLeafTTLAndPreservesAllowedSANs(t *testing.T) {
	caKey, caCrt, err := CreateCA("short-ca", 2048, 2*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := GenerateKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM, err := CreateCSR(leafKey, "leaf.example", []string{"api.example", "127.0.0.1"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := DecodeCSR(csrPEM)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := SignCSR(csr, caCrt, caKey, SignOpts{
		TTL:         48 * time.Hour,
		AllowAltSAN: true,
		DNSAltNames: []string{"extra.example"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if leaf.NotAfter.After(caCrt.NotAfter) {
		t.Fatalf("leaf NotAfter %s outlives CA %s", leaf.NotAfter, caCrt.NotAfter)
	}
	for _, name := range []string{"leaf.example", "api.example", "extra.example"} {
		if !slices.Contains(leaf.DNSNames, name) {
			t.Fatalf("DNSNames = %v, want %s", leaf.DNSNames, name)
		}
	}
	if !slices.ContainsFunc(leaf.IPAddresses, func(ip net.IP) bool { return ip.String() == "127.0.0.1" }) {
		t.Fatalf("IPAddresses = %v, want 127.0.0.1", leaf.IPAddresses)
	}
}

func TestEncodeDecodeCertAndCRL(t *testing.T) {
	caKey, caCrt, err := CreateCA("encode-ca", 2048, 0)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := EncodeCert(caCrt)
	blk, _ := pem.Decode(certPEM)
	if blk == nil || blk.Type != "CERTIFICATE" {
		t.Fatalf("EncodeCert block = %#v", blk)
	}
	got, err := DecodeCert(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	if got.SerialNumber.Cmp(caCrt.SerialNumber) != 0 {
		t.Fatalf("decoded serial = %s, want %s", got.SerialNumber, caCrt.SerialNumber)
	}

	crlPEM, err := CreateCRL(caCrt, caKey, []RevokedEntry{{Serial: big.NewInt(42), When: time.Unix(123, 0)}}, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	blk, _ = pem.Decode(crlPEM)
	if blk == nil || blk.Type != "X509 CRL" {
		t.Fatalf("CreateCRL block = %#v", blk)
	}
	crl, err := x509.ParseRevocationList(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if len(crl.RevokedCertificateEntries) != 1 || crl.RevokedCertificateEntries[0].SerialNumber.Cmp(big.NewInt(42)) != 0 {
		t.Fatalf("revoked entries = %+v", crl.RevokedCertificateEntries)
	}
}

func TestPublicKeyEncodingAndFingerprints(t *testing.T) {
	key, err := GenerateKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	pubPEM, err := EncodePublicKey(key)
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(pubPEM)
	if blk == nil || blk.Type != "PUBLIC KEY" {
		t.Fatalf("public key block = %#v", blk)
	}
	pub, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	parsed, ok := pub.(*rsa.PublicKey)
	if !ok || parsed.N.Cmp(key.N) != 0 || parsed.E != key.E {
		t.Fatal("decoded public key does not match original")
	}

	sum := sha256.Sum256([]byte("cert"))
	want := strings.ToUpper(hex.EncodeToString(sum[:]))
	want = strings.Join(chunk2(want), ":")
	fp := Fingerprints([]byte("cert"))
	if fp["SHA256"] != want || fp["default"] != want || fp["SHA1"] == "" {
		t.Fatalf("Fingerprints = %v, want SHA256/default %s", fp, want)
	}
}

func chunk2(s string) []string {
	out := make([]string, 0, len(s)/2)
	for i := 0; i < len(s); i += 2 {
		out = append(out, s[i:i+2])
	}
	return out
}
