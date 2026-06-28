package ca

import (
	"bytes"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ncode/facts-ca/internal/capi"
	"github.com/ncode/facts-ca/pki"
)

func benchmarkCSRPEM(tb testing.TB, key *rsa.PrivateKey, name string) []byte {
	tb.Helper()
	csr, err := pki.CreateCSR(key, name, []string{"127.0.0.1"}, nil)
	if err != nil {
		tb.Fatal(err)
	}
	return csr
}

func BenchmarkHandler(b *testing.B) {
	key, err := pki.GenerateKey(2048)
	if err != nil {
		b.Fatal(err)
	}
	b.Run("get-ca-cert", func(b *testing.B) {
		c := newTestCA(b, Options{})
		h := c.Handler()
		b.ReportAllocs()
		for b.Loop() {
			req := httptest.NewRequest(http.MethodGet, capi.Base+"/certificate/ca", nil)
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if rr.Code != http.StatusOK {
				b.Fatalf("status = %d", rr.Code)
			}
		}
	})
	b.Run("put-csr-autosign", func(b *testing.B) {
		c := newTestCA(b, Options{AutosignAll: true, AllowAltSAN: true})
		h := c.Handler()
		i := 0
		b.ReportAllocs()
		for b.Loop() {
			b.StopTimer()
			name := fmt.Sprintf("node-%d", i)
			i++
			csr := benchmarkCSRPEM(b, key, name)
			req := httptest.NewRequest(http.MethodPut, capi.Base+"/certificate_request/"+name, bytes.NewReader(csr))
			rr := httptest.NewRecorder()
			b.StartTimer()
			h.ServeHTTP(rr, req)
			if rr.Code != http.StatusOK {
				b.Fatalf("status = %d: %s", rr.Code, rr.Body.String())
			}
		}
	})
	b.Run("get-statuses-100", func(b *testing.B) {
		c := newTestCA(b, Options{AutosignAll: true})
		for i := range 100 {
			name := fmt.Sprintf("node-%03d", i)
			if code := submit(b, c, name, benchmarkCSRPEM(b, key, name)); code != http.StatusOK {
				b.Fatalf("submit = %d", code)
			}
		}
		h := c.Handler()
		b.ReportAllocs()
		for b.Loop() {
			req := httptest.NewRequest(http.MethodGet, capi.Base+"/certificate_statuses/all", nil)
			req.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{c.Cert()}}}
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if rr.Code != http.StatusOK {
				b.Fatalf("status = %d", rr.Code)
			}
		}
	})
}
