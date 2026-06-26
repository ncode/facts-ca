// Package ssldir is the agent-side certificate store, laid out exactly like a
// Puppet ssldir so facts-ca-cli's files are interchangeable with a Puppet
// agent's:
//
//	<dir>/private_keys/<certname>.pem
//	<dir>/public_keys/<certname>.pem
//	<dir>/certs/<certname>.pem
//	<dir>/certs/ca.pem
//	<dir>/certificate_requests/<certname>.pem
//	<dir>/crl.pem
package ssldir

import (
	"crypto/rsa"
	"os"
	"path/filepath"

	"github.com/ncode/facts-ca/internal/pki"
)

type SSLDir struct {
	dir      string
	certname string
}

func New(dir, certname string) *SSLDir { return &SSLDir{dir: dir, certname: certname} }

func (s *SSLDir) PrivateKeyPath() string {
	return filepath.Join(s.dir, "private_keys", s.certname+".pem")
}
func (s *SSLDir) PublicKeyPath() string {
	return filepath.Join(s.dir, "public_keys", s.certname+".pem")
}
func (s *SSLDir) CertPath() string   { return filepath.Join(s.dir, "certs", s.certname+".pem") }
func (s *SSLDir) CACertPath() string { return filepath.Join(s.dir, "certs", "ca.pem") }
func (s *SSLDir) CSRPath() string {
	return filepath.Join(s.dir, "certificate_requests", s.certname+".pem")
}
func (s *SSLDir) CRLPath() string { return filepath.Join(s.dir, "crl.pem") }

// Ensure creates the standard subdirectories (private_keys is locked to 0700).
func (s *SSLDir) Ensure() error {
	for _, sub := range []string{"public_keys", "certs", "certificate_requests"} {
		if err := os.MkdirAll(filepath.Join(s.dir, sub), 0o755); err != nil {
			return err
		}
	}
	return os.MkdirAll(filepath.Join(s.dir, "private_keys"), 0o700)
}

func exists(p string) bool { _, err := os.Stat(p); return err == nil }

func (s *SSLDir) HasCert() bool { return exists(s.CertPath()) }
func (s *SSLDir) HasKey() bool  { return exists(s.PrivateKeyPath()) }

// LoadOrCreateKey returns the agent's private key, generating and persisting one
// (plus its public key) on first use. The private_keys dir is locked to 0700.
func (s *SSLDir) LoadOrCreateKey(bits int) (*rsa.PrivateKey, error) {
	if b, err := os.ReadFile(s.PrivateKeyPath()); err == nil {
		return pki.DecodePrivateKey(b)
	}
	key, err := pki.GenerateKey(bits)
	if err != nil {
		return nil, err
	}
	_ = os.Chmod(filepath.Dir(s.PrivateKeyPath()), 0o700)
	if err := os.WriteFile(s.PrivateKeyPath(), pki.EncodePrivateKey(key), 0o600); err != nil {
		return nil, err
	}
	pub, err := pki.EncodePublicKey(key)
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(s.PublicKeyPath(), pub, 0o644); err != nil {
		return nil, err
	}
	return key, nil
}

// WriteCSR / WriteCert / WriteCACert / WriteCRL persist PEM payloads.
func (s *SSLDir) WriteCSR(pem []byte) error  { return os.WriteFile(s.CSRPath(), pem, 0o644) }
func (s *SSLDir) WriteCert(pem []byte) error { return os.WriteFile(s.CertPath(), pem, 0o644) }
func (s *SSLDir) WriteCACert(pem []byte) error {
	return os.WriteFile(s.CACertPath(), pem, 0o644)
}
func (s *SSLDir) WriteCRL(pem []byte) error { return os.WriteFile(s.CRLPath(), pem, 0o644) }

func (s *SSLDir) ReadCACert() ([]byte, error) { return os.ReadFile(s.CACertPath()) }
