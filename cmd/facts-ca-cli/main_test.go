package main

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/ncode/facts-ca/agent"
	capkg "github.com/ncode/facts-ca/ca"
)

func TestResolveCommonDefaultsPortAndDiscoversCertname(t *testing.T) {
	dir := t.TempDir()
	certs := filepath.Join(dir, "certs")
	if err := os.MkdirAll(certs, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(certs, "ca.pem"), []byte("ca"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(certs, "node1.pem"), []byte("cert"), 0o644); err != nil {
		t.Fatal(err)
	}

	c, err := resolveCommon(map[string]string{"server": "ca.example.com", "ssldir": dir})
	if err != nil {
		t.Fatal(err)
	}
	if c.server != "ca.example.com:8140" || c.host != "ca.example.com" || c.certname != "node1" || c.dir != dir {
		t.Fatalf("resolved common = %+v", c)
	}
}

func TestDiscoverCertnameRequiresExactlyOneLeaf(t *testing.T) {
	dir := t.TempDir()
	if got := discoverCertname(dir); got != "" {
		t.Fatalf("discover missing certs = %q, want empty", got)
	}
	certs := filepath.Join(dir, "certs")
	if err := os.MkdirAll(certs, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"ca.pem", "notes.txt"} {
		if err := os.WriteFile(filepath.Join(certs, name), nil, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if got := discoverCertname(dir); got != "" {
		t.Fatalf("discover with only CA/non-PEM = %q, want empty", got)
	}
	if err := os.WriteFile(filepath.Join(certs, "node1.pem"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if got := discoverCertname(dir); got != "node1" {
		t.Fatalf("discover single leaf = %q, want node1", got)
	}
	if err := os.WriteFile(filepath.Join(certs, "node2.pem"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if got := discoverCertname(dir); got != "" {
		t.Fatalf("discover ambiguous leaves = %q, want empty", got)
	}
}

func TestParseCommonAndCollectExtensions(t *testing.T) {
	attrs := filepath.Join(t.TempDir(), "csr_attributes.yaml")
	if err := os.WriteFile(attrs, []byte("extension_requests:\n  pp_role: file\n  pp_environment: prod\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	args := []string{
		"--server", "ca:8140",
		"--onetime",
		"--csr-attributes", attrs,
		"--ext", "pp_role=flag",
		"--ext=pp_uuid=123",
		"pos",
	}
	opts, pos := parseCommon(args)
	if opts["server"] != "ca:8140" || opts["onetime"] != "true" || opts["csr-attributes"] != attrs {
		t.Fatalf("opts = %v", opts)
	}
	if !slices.Equal(pos, []string{"pos"}) {
		t.Fatalf("positional = %v", pos)
	}

	ext, err := collectExtensions(opts, args)
	if err != nil {
		t.Fatal(err)
	}
	if ext["pp_role"] != "flag" || ext["pp_environment"] != "prod" || ext["pp_uuid"] != "123" {
		t.Fatalf("extensions = %v", ext)
	}
}

func TestBootstrapCAAdminAndMTLSCommands(t *testing.T) {
	server := cliCAServer(t, true, true)
	dir := t.TempDir()
	attrs := filepath.Join(t.TempDir(), "csr_attributes.yaml")
	if err := os.WriteFile(attrs, []byte("custom_attributes:\n  1.2.840.113549.1.9.7: secret\nextension_requests:\n  pp_environment: test\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	args := []string{
		"--server", server,
		"--certname", "client",
		"--ssldir", dir,
		"--onetime",
		"--keylength", "2048",
		"--csr-attributes", attrs,
		"--ext", "pp_role=admin",
	}
	if err := cmdBootstrap(args); err != nil {
		t.Fatalf("cmdBootstrap: %v", err)
	}
	if err := cmdBootstrap(args); err != nil {
		t.Fatalf("cmdBootstrap reuse: %v", err)
	}
	if err := cmdCA([]string{"--server", server, "--ssldir", dir, "list"}); err != nil {
		t.Fatalf("cmdCA list: %v", err)
	}

	serverID, err := agent.Enroll(context.Background(), agent.Config{
		Server: server, Certname: "svc", KeyBits: 2048,
		DNSAltNames: []string{"127.0.0.1"}, TrustOnFirstUse: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	ln, err := serverID.Listener("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	svc := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok\n")
	})}
	go func() { _ = svc.Serve(ln) }()
	t.Cleanup(func() { _ = svc.Close() })

	if err := cmdMTLS([]string{"--server", server, "--ssldir", dir, "--url", "https://" + ln.Addr().String() + "/"}); err != nil {
		t.Fatalf("cmdMTLS: %v", err)
	}
	if err := cmdCA([]string{"--server", server, "--ssldir", dir, "revoke", "client"}); err != nil {
		t.Fatalf("cmdCA revoke: %v", err)
	}
	if err := cmdCA([]string{"--server", server, "--ssldir", dir, "sign"}); err == nil {
		t.Fatal("cmdCA sign without name should fail")
	}
	if err := cmdCA([]string{"--server", server, "--ssldir", dir, "bogus"}); err == nil {
		t.Fatal("cmdCA unknown subcommand succeeded")
	}
}

func TestCommandErrorPaths(t *testing.T) {
	if _, err := resolveCommon(map[string]string{}); err == nil {
		t.Fatal("resolveCommon without server succeeded")
	}
	if _, err := resolveCommon(map[string]string{"server": "ca", "certname": "../bad"}); err == nil {
		t.Fatal("resolveCommon with invalid certname succeeded")
	}
	if err := cmdBootstrap([]string{"--server", "ca", "--certname", "node1", "--keylength", "1024"}); err == nil {
		t.Fatal("cmdBootstrap accepted weak keylength")
	}
	if err := cmdBootstrap([]string{"--server", "ca", "--certname", "node1", "--csr-attributes", filepath.Join(t.TempDir(), "missing.yaml")}); err == nil {
		t.Fatal("cmdBootstrap accepted missing csr_attributes")
	}
	if err := cmdMTLS([]string{"--server", "ca"}); err == nil {
		t.Fatal("cmdMTLS without url succeeded")
	}
	if err := cmdMTLS([]string{"--server", "ca", "--url", "https://127.0.0.1/"}); err == nil {
		t.Fatal("cmdMTLS without bootstrapped identity succeeded")
	}
	if err := cmdCA(nil); err == nil {
		t.Fatal("cmdCA without subcommand succeeded")
	}
	if _, _, err := httpGET(http.DefaultClient, "://bad-url"); err == nil {
		t.Fatal("httpGET accepted malformed URL")
	}
	if _, _, err := httpPUT(http.DefaultClient, "://bad-url", nil); err == nil {
		t.Fatal("httpPUT accepted malformed URL")
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("body"))
	}))
	t.Cleanup(srv.Close)
	body, code, err := httpGET(srv.Client(), srv.URL)
	if err != nil || code != http.StatusOK || string(body) != "body" {
		t.Fatalf("httpGET server = body %q code %d err %v", body, code, err)
	}
	_, code, err = httpPUT(srv.Client(), srv.URL, []byte("x"))
	if err != nil || code != http.StatusOK {
		t.Fatalf("httpPUT server = code %d err %v", code, err)
	}
}

func TestCLIMainVersion(t *testing.T) {
	old := os.Args
	t.Cleanup(func() { os.Args = old })
	os.Args = []string{"facts-ca-cli", "version"}
	main()
}

func TestCLIMainDispatchSuccess(t *testing.T) {
	server := cliCAServer(t, true, true)
	dir := t.TempDir()
	runMain(t, "facts-ca-cli", "bootstrap", "--server", server, "--certname", "main-client", "--ssldir", dir, "--onetime", "--keylength", "2048")
	runMain(t, "facts-ca-cli", "ca", "--server", server, "--ssldir", dir, "list")

	serverID, err := agent.Enroll(context.Background(), agent.Config{
		Server: server, Certname: "main-svc", KeyBits: 2048,
		DNSAltNames: []string{"127.0.0.1"}, TrustOnFirstUse: true,
	})
	if err != nil {
		t.Fatal(err)
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
	runMain(t, "facts-ca-cli", "mtls", "--server", server, "--ssldir", dir, "--url", "https://"+ln.Addr().String()+"/")
}

func TestSmallCLIUtils(t *testing.T) {
	if got := splitComma(" a, ,b,, c "); !slices.Equal(got, []string{"a", "b", "c"}) {
		t.Fatalf("splitComma = %v", got)
	}
	if atoiOr("42", 7) != 42 || atoiOr("-1", 7) != 7 || atoiOr("bad", 7) != 7 {
		t.Fatal("atoiOr did not honor valid-positive-only fallback")
	}
	if durationOr("2s", time.Minute) != 2*time.Second || durationOr("bad", time.Minute) != time.Minute {
		t.Fatal("durationOr did not parse valid duration or fall back on invalid input")
	}
	if got := joinKeys(map[string]string{"b": "", "a": ""}); got != "a, b" {
		t.Fatalf("joinKeys = %q", got)
	}
}

func runMain(t *testing.T, args ...string) {
	t.Helper()
	old := os.Args
	defer func() { os.Args = old }()
	os.Args = args
	main()
}

func cliCAServer(t *testing.T, autosign, allowSAN bool) string {
	t.Helper()
	c, err := capkg.Init(capkg.Options{
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
	return ln.Addr().String()
}
