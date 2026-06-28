package ssldir

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadOrCreateKeyCreatesLayoutAndReusesKey(t *testing.T) {
	dir := t.TempDir()
	ssl := New(dir, "node1")

	key, err := ssl.LoadOrCreateKey(2048)
	if err != nil {
		t.Fatalf("LoadOrCreateKey on fresh dir: %v", err)
	}
	if !fileExists(t, ssl.PrivateKeyPath()) || !fileExists(t, ssl.PublicKeyPath()) {
		t.Fatalf("expected private and public keys in %s", dir)
	}
	if mode := fileMode(t, filepath.Join(dir, "private_keys")); mode != 0o700 {
		t.Fatalf("private_keys mode = %o, want 700", mode)
	}

	again, err := ssl.LoadOrCreateKey(2048)
	if err != nil {
		t.Fatalf("LoadOrCreateKey reuse: %v", err)
	}
	if again.N.Cmp(key.N) != 0 || again.E != key.E {
		t.Fatal("LoadOrCreateKey generated a new key instead of reusing the stored one")
	}
}

func TestPathsAndPEMWriters(t *testing.T) {
	dir := t.TempDir()
	ssl := New(dir, "node1")
	if !strings.HasSuffix(ssl.PrivateKeyPath(), filepath.Join("private_keys", "node1.pem")) {
		t.Fatalf("PrivateKeyPath = %s", ssl.PrivateKeyPath())
	}
	if !strings.HasSuffix(ssl.PublicKeyPath(), filepath.Join("public_keys", "node1.pem")) {
		t.Fatalf("PublicKeyPath = %s", ssl.PublicKeyPath())
	}
	if !strings.HasSuffix(ssl.CSRPath(), filepath.Join("certificate_requests", "node1.pem")) {
		t.Fatalf("CSRPath = %s", ssl.CSRPath())
	}
	if ssl.HasCert() || ssl.HasKey() {
		t.Fatal("fresh ssldir should not report cert or key")
	}

	if err := ssl.Ensure(); err != nil {
		t.Fatal(err)
	}
	writes := []struct {
		name string
		path string
		fn   func([]byte) error
		data []byte
	}{
		{"csr", ssl.CSRPath(), ssl.WriteCSR, []byte("csr")},
		{"cert", ssl.CertPath(), ssl.WriteCert, []byte("cert")},
		{"ca", ssl.CACertPath(), ssl.WriteCACert, []byte("ca")},
		{"crl", ssl.CRLPath(), ssl.WriteCRL, []byte("crl")},
	}
	for _, tt := range writes {
		if err := tt.fn(tt.data); err != nil {
			t.Fatalf("Write%s: %v", tt.name, err)
		}
		got, err := os.ReadFile(tt.path)
		if err != nil {
			t.Fatal(err)
		}
		if string(got) != string(tt.data) {
			t.Fatalf("%s contents = %q, want %q", tt.path, got, tt.data)
		}
	}
	gotCA, err := ssl.ReadCACert()
	if err != nil {
		t.Fatal(err)
	}
	if string(gotCA) != "ca" {
		t.Fatalf("ReadCACert = %q", gotCA)
	}
	if !ssl.HasCert() {
		t.Fatal("HasCert stayed false after WriteCert")
	}
}

func fileExists(t *testing.T, path string) bool {
	t.Helper()
	_, err := os.Stat(path)
	return err == nil
}

func fileMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return st.Mode().Perm()
}
