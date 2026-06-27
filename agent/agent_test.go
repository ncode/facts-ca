package agent

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ncode/facts-ca/ca"
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

func fileExists(p string) bool { _, err := os.Stat(p); return err == nil }
