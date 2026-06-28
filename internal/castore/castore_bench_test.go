package castore

import (
	"context"
	"crypto/rsa"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/ncode/facts-ca/internal/capi"
	"github.com/ncode/facts-ca/internal/ppext"
	"github.com/ncode/facts-ca/pki"
)

func benchmarkCA(tb testing.TB, opts Options) *CA {
	tb.Helper()
	ca, err := Init(tb.TempDir(), "bench-ca", 2048, opts)
	if err != nil {
		tb.Fatal(err)
	}
	return ca
}

func benchmarkKey(tb testing.TB) *rsa.PrivateKey {
	tb.Helper()
	key, err := pki.GenerateKey(2048)
	if err != nil {
		tb.Fatal(err)
	}
	return key
}

func benchmarkCSR(tb testing.TB, key *rsa.PrivateKey, name string) []byte {
	tb.Helper()
	csr, err := pki.CreateCSR(key, name, []string{"127.0.0.1"}, nil)
	if err != nil {
		tb.Fatal(err)
	}
	return csr
}

func benchmarkSigned(tb testing.TB, ca *CA, key *rsa.PrivateKey, name string) {
	tb.Helper()
	signed, err := ca.SubmitCSR(name, benchmarkCSR(tb, key, name))
	if err != nil {
		tb.Fatal(err)
	}
	if !signed {
		tb.Fatalf("%s was not autosigned", name)
	}
}

func BenchmarkSubmitCSR(b *testing.B) {
	key := benchmarkKey(b)
	b.Run("pending", func(b *testing.B) {
		ca := benchmarkCA(b, Options{})
		i := 0
		b.ReportAllocs()
		for b.Loop() {
			b.StopTimer()
			name := fmt.Sprintf("node-%d", i)
			i++
			csr := benchmarkCSR(b, key, name)
			b.StartTimer()
			signed, err := ca.SubmitCSR(name, csr)
			if err != nil {
				b.Fatal(err)
			}
			if signed {
				b.Fatal("unexpected autosign")
			}
		}
	})
	b.Run("autosign", func(b *testing.B) {
		ca := benchmarkCA(b, Options{AutosignAll: true, AllowAltSAN: true})
		i := 0
		b.ReportAllocs()
		for b.Loop() {
			b.StopTimer()
			name := fmt.Sprintf("node-%d", i)
			i++
			csr := benchmarkCSR(b, key, name)
			b.StartTimer()
			signed, err := ca.SubmitCSR(name, csr)
			if err != nil {
				b.Fatal(err)
			}
			if !signed {
				b.Fatal("not autosigned")
			}
		}
	})
}

func BenchmarkStatus(b *testing.B) {
	key := benchmarkKey(b)
	for _, revoked := range []int{0, 100} {
		b.Run(fmt.Sprintf("revoked=%d", revoked), func(b *testing.B) {
			ca := benchmarkCA(b, Options{AutosignAll: true})
			benchmarkSigned(b, ca, key, "target")
			for i := range revoked {
				name := fmt.Sprintf("revoked-%d", i)
				benchmarkSigned(b, ca, key, name)
				if err := ca.Revoke(name); err != nil {
					b.Fatal(err)
				}
			}
			b.ReportAllocs()
			for b.Loop() {
				st, err := ca.Status("target")
				if err != nil {
					b.Fatal(err)
				}
				if st.State != capi.StateSigned {
					b.Fatalf("state = %q", st.State)
				}
			}
		})
	}
}

func BenchmarkStatuses(b *testing.B) {
	key := benchmarkKey(b)
	for _, n := range []int{10, 100} {
		b.Run(fmt.Sprintf("signed=%d", n), func(b *testing.B) {
			ca := benchmarkCA(b, Options{AutosignAll: true})
			for i := range n {
				benchmarkSigned(b, ca, key, fmt.Sprintf("node-%03d", i))
			}
			b.ReportAllocs()
			for b.Loop() {
				list, err := ca.Statuses()
				if err != nil {
					b.Fatal(err)
				}
				if len(list) != n {
					b.Fatalf("statuses = %d, want %d", len(list), n)
				}
			}
		})
	}
}

func BenchmarkOpen(b *testing.B) {
	dir := b.TempDir()
	if _, err := Init(dir, "bench-ca", 2048, Options{}); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		ca, err := Open(dir, Options{})
		if err != nil {
			b.Fatal(err)
		}
		if ca.Cert() == nil {
			b.Fatal("missing cert")
		}
	}
}

func BenchmarkServerTLSCert(b *testing.B) {
	ca := benchmarkCA(b, Options{})
	if _, err := ca.ServerTLSCert([]string{"127.0.0.1", "ca.local"}); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		cert, err := ca.ServerTLSCert([]string{"127.0.0.1", "ca.local"})
		if err != nil {
			b.Fatal(err)
		}
		if cert.Leaf == nil {
			b.Fatal("missing leaf")
		}
	}
}

func BenchmarkBuildPolicyInput(b *testing.B) {
	key := benchmarkKey(b)
	exts, err := ppext.BuildExtensions(map[string]string{
		"pp_role":                  "web",
		"pp_authorization":         "true",
		"1.3.6.1.4.1.34380.1.2.99": "custom",
	})
	if err != nil {
		b.Fatal(err)
	}
	csrPEM, err := pki.CreateCSR(key, "node.example", []string{"api.example", "127.0.0.1"}, exts)
	if err != nil {
		b.Fatal(err)
	}
	csr, err := pki.DecodeCSR(csrPEM)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		input, err := buildPolicyInput("node.example", csr, "203.0.113.9")
		if err != nil {
			b.Fatal(err)
		}
		if input.Certname == "" {
			b.Fatal("empty certname")
		}
	}
}

func BenchmarkRunAutosignPolicy(b *testing.B) {
	b.Setenv("FACTS_CA_POLICY_TEST_HELPER", "approve")
	exe, err := os.Executable()
	if err != nil {
		b.Fatal(err)
	}
	input := policyInput{Version: 1, Certname: "node"}
	b.ReportAllocs()
	for b.Loop() {
		got := runAutosignPolicy(context.Background(), exe, 5*time.Second, input)
		if got.outcome != policyApproved {
			b.Fatalf("outcome = %v err=%v stderr=%q", got.outcome, got.err, got.stderr)
		}
	}
}
