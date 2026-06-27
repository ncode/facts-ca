package pki

import (
	"crypto/x509"
	"encoding/pem"
	"testing"
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
