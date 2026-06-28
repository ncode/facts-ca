package pki

import (
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/ncode/facts-ca/internal/ppext"
)

func BenchmarkGenerateKey(b *testing.B) {
	for _, bits := range []int{2048, DefaultKeyBits} {
		b.Run(fmt.Sprintf("bits=%d", bits), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				key, err := GenerateKey(bits)
				if err != nil {
					b.Fatal(err)
				}
				if key.N.Sign() == 0 {
					b.Fatal("empty key")
				}
			}
		})
	}
}

func BenchmarkCreateCSR(b *testing.B) {
	key, err := GenerateKey(2048)
	if err != nil {
		b.Fatal(err)
	}
	exts, err := ppext.BuildExtensions(map[string]string{
		"pp_role":          "web",
		"pp_authorization": "true",
	})
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		csr, err := CreateCSR(key, "node.example", []string{"api.example", "127.0.0.1"}, exts)
		if err != nil {
			b.Fatal(err)
		}
		if len(csr) == 0 {
			b.Fatal("empty CSR")
		}
	}
}

func BenchmarkSignCSR(b *testing.B) {
	caKey, caCrt, err := CreateCA("bench-ca", 2048, 0)
	if err != nil {
		b.Fatal(err)
	}
	leafKey, err := GenerateKey(2048)
	if err != nil {
		b.Fatal(err)
	}
	csrPEM, err := CreateCSR(leafKey, "node.example", []string{"api.example"}, nil)
	if err != nil {
		b.Fatal(err)
	}
	csr, err := DecodeCSR(csrPEM)
	if err != nil {
		b.Fatal(err)
	}
	opts := SignOpts{Serial: big.NewInt(2), AllowAltSAN: true}
	b.ReportAllocs()
	for b.Loop() {
		crt, err := SignCSR(csr, caCrt, caKey, opts)
		if err != nil {
			b.Fatal(err)
		}
		if crt.Subject.CommonName == "" {
			b.Fatal("empty certificate subject")
		}
	}
}

func BenchmarkCreateCRL(b *testing.B) {
	caKey, caCrt, err := CreateCA("bench-ca", 2048, 0)
	if err != nil {
		b.Fatal(err)
	}
	for _, n := range []int{0, 100, 1000} {
		revoked := make([]RevokedEntry, n)
		for i := range revoked {
			revoked[i] = RevokedEntry{Serial: big.NewInt(int64(i + 2)), When: time.Unix(int64(i), 0)}
		}
		b.Run(fmt.Sprintf("revoked=%d", n), func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				crl, err := CreateCRL(caCrt, caKey, revoked, 0)
				if err != nil {
					b.Fatal(err)
				}
				if len(crl) == 0 {
					b.Fatal("empty CRL")
				}
			}
		})
	}
}

func BenchmarkPEM(b *testing.B) {
	caKey, caCrt, err := CreateCA("bench-ca", 2048, 0)
	if err != nil {
		b.Fatal(err)
	}
	certPEM := EncodeCert(caCrt)
	keyPEM := EncodePrivateKey(caKey)
	leafKey, err := GenerateKey(2048)
	if err != nil {
		b.Fatal(err)
	}
	csrPEM, err := CreateCSR(leafKey, "node.example", nil, nil)
	if err != nil {
		b.Fatal(err)
	}
	b.Run("encode-cert", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if len(EncodeCert(caCrt)) == 0 {
				b.Fatal("empty cert")
			}
		}
	})
	b.Run("encode-private-key", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if len(EncodePrivateKey(caKey)) == 0 {
				b.Fatal("empty key")
			}
		}
	})
	b.Run("decode-cert", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			crt, err := DecodeCert(certPEM)
			if err != nil {
				b.Fatal(err)
			}
			if crt.SerialNumber.Sign() == 0 {
				b.Fatal("empty serial")
			}
		}
	})
	b.Run("decode-private-key", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			key, err := DecodePrivateKey(keyPEM)
			if err != nil {
				b.Fatal(err)
			}
			if key.N.Sign() == 0 {
				b.Fatal("empty key")
			}
		}
	})
	b.Run("decode-csr", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			csr, err := DecodeCSR(csrPEM)
			if err != nil {
				b.Fatal(err)
			}
			if csr.Subject.CommonName == "" {
				b.Fatal("empty CSR subject")
			}
		}
	})
}

func BenchmarkFingerprints(b *testing.B) {
	_, caCrt, err := CreateCA("bench-ca", 2048, 0)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		fp := Fingerprints(caCrt.Raw)
		if fp["default"] == "" {
			b.Fatal("missing fingerprint")
		}
	}
}
