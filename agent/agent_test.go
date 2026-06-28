package agent

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ncode/facts-ca/ca"
	"github.com/ncode/facts-ca/pki"
)

// caServer starts an in-process CA over mTLS on 127.0.0.1 and returns its
// host:port and CA PEM. allowSAN lets enrolled leaves keep requested SANs.
func caServer(t *testing.T, autosign, allowSAN bool) (server string, caPEM []byte) {
	t.Helper()
	c, err := ca.Init(ca.Options{
		Dir:         t.TempDir(),
		CAName:      "test-ca",
		Hostnames:   []string{"127.0.0.1"},
		AutosignAll: autosign,
		AllowAltSAN: allowSAN,
	})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := c.ServerTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", cfg)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: c.Handler()}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String(), c.CACertPEM()
}

func TestEnrollDiskAndReuse(t *testing.T) {
	server, _ := caServer(t, true, false)
	dir := t.TempDir()
	cfg := Config{Server: server, Certname: "node1", Dir: dir, KeyBits: 2048, TrustOnFirstUse: true}

	id1, err := Enroll(context.Background(), cfg)
	if err != nil {
		t.Fatalf("first enroll: %v", err)
	}
	if !fileExists(filepath.Join(dir, "certs", "node1.pem")) {
		t.Fatal("disk mode did not write the leaf cert")
	}

	id2, err := Enroll(context.Background(), cfg)
	if err != nil {
		t.Fatalf("second enroll (reuse): %v", err)
	}
	s1 := id1.Certificate().Leaf.SerialNumber
	s2 := id2.Certificate().Leaf.SerialNumber
	if s1.Cmp(s2) != 0 {
		t.Fatalf("reuse should return the same cert; serials %s != %s", s1, s2)
	}
}

func TestEnrollEphemeralWritesNothing(t *testing.T) {
	server, _ := caServer(t, true, false)
	// A scratch CWD so we can prove ephemeral mode touches no relative paths.
	scratch := t.TempDir()
	t.Chdir(scratch)

	id, err := Enroll(context.Background(), Config{Server: server, Certname: "ephem", KeyBits: 2048, TrustOnFirstUse: true})
	if err != nil {
		t.Fatalf("ephemeral enroll: %v", err)
	}
	if id.Certificate().Leaf == nil {
		t.Fatal("ephemeral identity has no leaf")
	}
	entries, err := os.ReadDir(scratch)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("ephemeral mode wrote files: %v", entries)
	}
}

func TestEnrollFingerprintMismatchRejected(t *testing.T) {
	server, _ := caServer(t, true, false)
	_, err := Enroll(context.Background(), Config{
		Server: server, Certname: "node1", KeyBits: 2048,
		CAFingerprint: "00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF",
	})
	if err == nil {
		t.Fatal("enroll should fail on CA fingerprint mismatch")
	}
}

func TestEnrollNoTrustConfigured(t *testing.T) {
	server, _ := caServer(t, true, false)
	_, err := Enroll(context.Background(), Config{Server: server, Certname: "node1", KeyBits: 2048})
	if err == nil {
		t.Fatal("enroll should fail with no pin and no TrustOnFirstUse")
	}
}

func TestEnrollPinnedCACert(t *testing.T) {
	server, caPEM := caServer(t, true, false)
	id, err := Enroll(context.Background(), Config{Server: server, Certname: "node1", KeyBits: 2048, CACert: caPEM})
	if err != nil {
		t.Fatalf("enroll with pinned CACert: %v", err)
	}
	if id.Certname() != "node1" {
		t.Fatalf("certname = %q", id.Certname())
	}
}

func TestEnrollUsesStoredCAPinWithoutTrustOnFirstUse(t *testing.T) {
	server, caPEM := caServer(t, true, false)
	dir := t.TempDir()
	certDir := filepath.Join(dir, "certs")
	if err := os.MkdirAll(certDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(certDir, "ca.pem"), caPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	id, err := Enroll(context.Background(), Config{Server: server, Certname: "stored-ca", Dir: dir, KeyBits: 2048})
	if err != nil {
		t.Fatalf("enroll with stored CA pin: %v", err)
	}
	if id.Certname() != "stored-ca" {
		t.Fatalf("certname = %q", id.Certname())
	}
}

func TestEnrollRejectsPinnedCACertFingerprintDisagreement(t *testing.T) {
	server, caPEM := caServer(t, true, false)
	_, err := Enroll(context.Background(), Config{
		Server: server, Certname: "pin-disagree", KeyBits: 2048,
		CACert: caPEM, CAFingerprint: "00:11:22",
	})
	if err == nil || !strings.Contains(err.Error(), "does not match CAFingerprint") {
		t.Fatalf("Enroll pin disagreement error = %v", err)
	}
}

func TestEnrollNoWaitReturnsPendingError(t *testing.T) {
	server, _ := caServer(t, false, false)
	_, err := Enroll(context.Background(), Config{Server: server, Certname: "pending-nowait", KeyBits: 2048, TrustOnFirstUse: true})
	if err == nil || !strings.Contains(err.Error(), "not yet signed") {
		t.Fatalf("Enroll no-wait error = %v, want not yet signed", err)
	}
}

func TestEnrollContextCancelWaiting(t *testing.T) {
	server, _ := caServer(t, false, false) // no autosign => CSR stays pending
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(200 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	_, err := Enroll(ctx, Config{
		Server: server, Certname: "slow", KeyBits: 2048,
		TrustOnFirstUse: true, WaitForCert: 30 * time.Second,
	})
	if err == nil {
		t.Fatal("enroll should fail when ctx is cancelled while waiting")
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("cancel was not honored promptly: took %s", time.Since(start))
	}
}

func TestMutualTLS(t *testing.T) {
	server, _ := caServer(t, true, true) // allowSAN so the server leaf keeps 127.0.0.1
	serverID, err := Enroll(context.Background(), Config{
		Server: server, Certname: "svc", KeyBits: 2048,
		DNSAltNames: []string{"127.0.0.1"}, TrustOnFirstUse: true,
	})
	if err != nil {
		t.Fatalf("enroll server identity: %v", err)
	}
	clientID, err := Enroll(context.Background(), Config{Server: server, Certname: "caller", KeyBits: 2048, TrustOnFirstUse: true})
	if err != nil {
		t.Fatalf("enroll client identity: %v", err)
	}

	ln, err := serverID.Listener("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	svc := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})}
	go func() { _ = svc.Serve(ln) }()
	t.Cleanup(func() { _ = svc.Close() })
	addr := ln.Addr().String()

	// Accept path: a CA-signed client is mutually authenticated.
	httpc := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{TLSClientConfig: clientID.ClientTLSConfig("127.0.0.1")}}
	resp, err := httpc.Get("https://" + addr + "/")
	if err != nil {
		t.Fatalf("mutually-authenticated GET failed: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	_ = resp.Body.Close()
	if string(body) != "ok" {
		t.Fatalf("body = %q", body)
	}

	// Reject path: an unsigned client (no cert) is refused. The GET drives the
	// full handshake+request so TLS 1.3's async client-cert failure surfaces.
	bad := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, // ponytail: skip server verify to isolate the client-cert requirement
	}}
	if resp, err := bad.Get("https://" + addr + "/"); err == nil {
		_ = resp.Body.Close()
		t.Fatal("server must reject a client with no certificate")
	}
}

func TestIdentityCertRotation(t *testing.T) {
	server, _ := caServer(t, true, false)
	id, err := Enroll(context.Background(), Config{Server: server, Certname: "rot1", KeyBits: 2048, TrustOnFirstUse: true})
	if err != nil {
		t.Fatal(err)
	}
	other, err := Enroll(context.Background(), Config{Server: server, Certname: "rot2", KeyBits: 2048, TrustOnFirstUse: true})
	if err != nil {
		t.Fatal(err)
	}
	id.setCert(other.Certificate()) // a renewer swaps the live cert
	if got := id.Certificate().Leaf.Subject.CommonName; got != "rot2" {
		t.Fatalf("rotation not reflected: CN = %q, want rot2", got)
	}
}

func TestIdentityTrustMaterialAndHTTPClient(t *testing.T) {
	server, _ := caServer(t, true, false)
	id, err := Enroll(context.Background(), Config{Server: server, Certname: "trustmat", KeyBits: 2048, TrustOnFirstUse: true})
	if err != nil {
		t.Fatal(err)
	}

	caPEM := id.CACertPEM()
	if len(caPEM) == 0 {
		t.Fatal("CACertPEM returned empty PEM")
	}
	caPEM[0] ^= 0xff
	if bytes.Equal(caPEM, id.CACertPEM()) {
		t.Fatal("CACertPEM returned mutable internal storage")
	}
	if _, err := id.Certificate().Leaf.Verify(x509.VerifyOptions{Roots: id.CAPool(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("identity CAPool does not verify its leaf: %v", err)
	}

	client := id.HTTPClient()
	if client.Timeout != 30*time.Second {
		t.Fatalf("HTTPClient timeout = %s, want 30s", client.Timeout)
	}
	tr, ok := client.Transport.(*http.Transport)
	if !ok || tr.TLSClientConfig == nil {
		t.Fatalf("HTTPClient transport = %#v", client.Transport)
	}
	cert, err := tr.TLSClientConfig.GetClientCertificate(nil)
	if err != nil {
		t.Fatal(err)
	}
	if cert.Leaf.Subject.CommonName != "trustmat" {
		t.Fatalf("HTTPClient client cert CN = %q", cert.Leaf.Subject.CommonName)
	}
}

func TestEnrollStoredCARespectsPin(t *testing.T) {
	server, caPEM := caServer(t, true, false)
	dir := t.TempDir()
	if _, err := Enroll(context.Background(), Config{Server: server, Certname: "pinned", Dir: dir, KeyBits: 2048, TrustOnFirstUse: true}); err != nil {
		t.Fatalf("initial enroll: %v", err)
	}
	// A wrong fingerprint pin against the already-stored CA must be rejected,
	// not silently accepted from disk.
	if _, err := Enroll(context.Background(), Config{
		Server: server, Certname: "pinned", Dir: dir, KeyBits: 2048,
		CAFingerprint: "00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF",
	}); err == nil {
		t.Fatal("stored CA must be rejected when it contradicts the configured pin")
	}
	// The matching CACert pin reuses the stored identity fine.
	if _, err := Enroll(context.Background(), Config{Server: server, Certname: "pinned", Dir: dir, KeyBits: 2048, CACert: caPEM}); err != nil {
		t.Fatalf("matching pin should reuse stored identity: %v", err)
	}
}

func TestEnrollRejectsWeakKey(t *testing.T) {
	server, _ := caServer(t, true, false)
	if _, err := Enroll(context.Background(), Config{Server: server, Certname: "weak", KeyBits: 1024, TrustOnFirstUse: true}); err == nil {
		t.Fatal("KeyBits below 2048 must be rejected")
	}
}

func TestLoadLocalOnly(t *testing.T) {
	server, _ := caServer(t, true, false)
	dir := t.TempDir()
	// Not bootstrapped yet => Load errors without any network or disk mutation.
	if _, err := Load(dir, "loadnode"); err == nil {
		t.Fatal("Load on an unprovisioned dir should error")
	}
	if _, err := Enroll(context.Background(), Config{Server: server, Certname: "loadnode", Dir: dir, KeyBits: 2048, TrustOnFirstUse: true}); err != nil {
		t.Fatal(err)
	}
	id, err := Load(dir, "loadnode")
	if err != nil {
		t.Fatalf("Load after bootstrap: %v", err)
	}
	if id.Certname() != "loadnode" {
		t.Fatalf("certname = %q", id.Certname())
	}
}

func TestValidationFailures(t *testing.T) {
	caKey, caCrt, err := pki.CreateCA("test-ca", 2048, 0)
	if err != nil {
		t.Fatal(err)
	}
	key, certPEM := signedLeaf(t, caKey, caCrt, "node1")
	otherKey, _ := pki.GenerateKey(2048)
	_, otherCACrt, err := pki.CreateCA("other-ca", 2048, 0)
	if err != nil {
		t.Fatal(err)
	}
	otherCAPEM := pki.EncodeCert(otherCACrt)
	caPEM := pki.EncodeCert(caCrt)

	tests := []struct {
		name    string
		certPEM []byte
		caPEM   []byte
		cert    string
		key     any
		want    string
	}{
		{"bad cert pem", []byte("nope"), caPEM, "node1", key, "not valid PEM"},
		{"bad ca pem", certPEM, []byte("nope"), "node1", key, "cannot parse pinned CA"},
		{"wrong ca", certPEM, otherCAPEM, "node1", key, "does not chain"},
		{"wrong certname", certPEM, caPEM, "other", key, "does not match requested"},
		{"wrong key", certPEM, caPEM, "node1", otherKey, "public key does not match"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateIssuedCert(tt.certPEM, tt.caPEM, tt.cert, tt.key.(*rsa.PrivateKey))
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("validateIssuedCert error = %v, want %q", err, tt.want)
			}
		})
	}

	if err := validatePinnedCA([]byte("bad"), Config{CACert: caPEM}); err == nil {
		t.Fatal("validatePinnedCA accepted corrupt stored CA")
	}
	if err := validatePinnedCA(caPEM, Config{CACert: otherCAPEM}); err == nil {
		t.Fatal("validatePinnedCA accepted mismatched CACert")
	}
	if err := validatePinnedCA([]byte("bad"), Config{CAFingerprint: "AA"}); err == nil {
		t.Fatal("validatePinnedCA accepted corrupt fingerprint CA")
	}
}

func TestNewEnrollerValidationAndHTTPHelpers(t *testing.T) {
	if _, err := Enroll(context.Background(), Config{}); err == nil {
		t.Fatal("Enroll without server succeeded")
	}
	if _, err := Load("", "node1"); err == nil {
		t.Fatal("Load without dir succeeded")
	}
	if _, err := Load(t.TempDir(), "../bad"); err == nil {
		t.Fatal("Load with invalid certname succeeded")
	}
	if _, err := newEnroller(Config{}); err == nil {
		t.Fatal("newEnroller without server succeeded")
	}
	if _, err := newEnroller(Config{Server: "ca", Certname: "../bad"}); err == nil {
		t.Fatal("newEnroller with invalid certname succeeded")
	}
	e, err := newEnroller(Config{Server: "ca.example.com", Certname: "node1"})
	if err != nil {
		t.Fatal(err)
	}
	if e.server != "ca.example.com:8140" {
		t.Fatalf("server = %q, want default Puppet port", e.server)
	}
	if _, err := newEnroller(Config{Server: "ca.example.com", Logger: slog.Default()}); err != nil {
		t.Fatalf("newEnroller with default certname and logger: %v", err)
	}
	if _, err := e.verifiedClient([]byte("bad pem"), nil); err == nil {
		t.Fatal("verifiedClient accepted bad CA PEM")
	}
	caKey, caCrt, err := pki.CreateCA("test-ca", 2048, 0)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, certPEM := signedLeaf(t, caKey, caCrt, "node1")
	leaf, err := pki.DecodeCert(certPEM)
	if err != nil {
		t.Fatal(err)
	}
	clientCert := &tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: leafKey, Leaf: leaf}
	client, err := e.verifiedClient(pki.EncodeCert(caCrt), clientCert)
	if err != nil {
		t.Fatal(err)
	}
	tr := client.Transport.(*http.Transport)
	if len(tr.TLSClientConfig.Certificates) != 1 {
		t.Fatal("verifiedClient did not attach client certificate")
	}
	if _, _, err := httpGET(context.Background(), http.DefaultClient, "://bad-url"); err == nil {
		t.Fatal("httpGET accepted malformed URL")
	}
	if _, _, err := httpPUT(context.Background(), http.DefaultClient, "://bad-url", nil); err == nil {
		t.Fatal("httpPUT accepted malformed URL")
	}

	badCA := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not a cert"))
	}))
	t.Cleanup(badCA.Close)
	e.server = strings.TrimPrefix(badCA.URL, "https://")
	if _, err := e.tofuFetchCA(context.Background()); err != nil {
		t.Fatalf("raw tofuFetchCA should return 200 body before caller validation: %v", err)
	}
	if _, err := Enroll(context.Background(), Config{Server: e.server, Certname: "bad-ca", KeyBits: 2048, TrustOnFirstUse: true}); err == nil || !strings.Contains(err.Error(), "not a certificate") {
		t.Fatalf("Enroll bad CA response error = %v", err)
	}

	nonOK := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "no", http.StatusTeapot)
	}))
	t.Cleanup(nonOK.Close)
	host := strings.TrimPrefix(nonOK.URL, "https://")
	e.server = host
	if _, err := e.tofuFetchCA(context.Background()); err == nil || !strings.Contains(err.Error(), "418") {
		t.Fatalf("tofuFetchCA non-OK error = %v, want 418", err)
	}

	huge := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.CopyN(w, zeroReader{}, maxResponseBytes+1)
	}))
	t.Cleanup(huge.Close)
	if _, _, err := httpGET(context.Background(), huge.Client(), huge.URL); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized response error = %v, want exceeds", err)
	}

	badBodyClient := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: errReader{}}, nil
	})}
	if _, _, err := httpGET(context.Background(), badBodyClient, "https://example.test"); err == nil {
		t.Fatal("httpGET with unreadable body succeeded")
	}
}

func signedLeaf(t *testing.T, caKey *rsa.PrivateKey, caCrt *x509.Certificate, name string) (*rsa.PrivateKey, []byte) {
	t.Helper()
	key, err := pki.GenerateKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	csrPEM, err := pki.CreateCSR(key, name, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := pki.DecodeCSR(csrPEM)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := pki.SignCSR(csr, caCrt, caKey, pki.SignOpts{})
	if err != nil {
		t.Fatal(err)
	}
	return key, pki.EncodeCert(leaf)
}

type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	clear(p)
	return len(p), nil
}

type errReader struct{}

func (errReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }
func (errReader) Close() error             { return nil }

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }
