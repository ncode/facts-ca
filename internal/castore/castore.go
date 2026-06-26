// Package castore is the facts-ca-server's on-disk certificate authority: it
// owns the cadir (ca_crt/ca_key/ca_crl/serial/inventory and the signed/ and
// requests/ trees), and implements submit/sign/revoke/list with autosign.
//
// The layout mirrors puppetserver's cadir so the files are inspectable with the
// same tools and an operator can point either at the other.
package castore

import (
	"bytes"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/ncode/facts-ca/internal/capi"
	"github.com/ncode/facts-ca/internal/pki"
	"github.com/ncode/facts-ca/internal/ppext"
)

// ValidName reports whether name is a safe, Puppet-style certname (shared with
// the client via capi so both guard filesystem paths identically).
func ValidName(name string) bool { return capi.ValidCertname(name) }

// CA is a loaded certificate authority rooted at a cadir.
type CA struct {
	dir string

	mu  sync.Mutex // guards serial file, inventory, signed/ and requests/ writes
	key *rsa.PrivateKey
	crt *x509.Certificate

	ttl         time.Duration // issued-cert lifetime (ca_ttl)
	autosignAll bool          // sign every incoming CSR (insecure; == `autosign = true`)
	allowAltSAN bool          // honor agent-requested subjectAltNames (Puppet default: false)
}

// Options configure Init/Open.
type Options struct {
	TTL         time.Duration // issued cert lifetime; 0 => pki.DefaultCATTL
	AutosignAll bool
	AllowAltSAN bool // honor SANs in agent CSRs; default false matches puppetserver
}

func (c *CA) path(parts ...string) string {
	return filepath.Join(append([]string{c.dir}, parts...)...)
}

// Init creates a fresh CA in dir (failing if one already exists) and returns it.
func Init(dir, caName string, bits int, opts Options) (*CA, error) {
	if _, err := os.Stat(filepath.Join(dir, "ca_crt.pem")); err == nil {
		return nil, fmt.Errorf("CA already initialized at %s", dir)
	}
	for _, sub := range []string{"", "signed", "requests"} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0o755); err != nil {
			return nil, err
		}
	}
	key, crt, err := pki.CreateCA(caName, bits, 0)
	if err != nil {
		return nil, err
	}
	c := &CA{dir: dir, key: key, crt: crt, ttl: opts.TTL, autosignAll: opts.AutosignAll, allowAltSAN: opts.AllowAltSAN}
	if c.ttl <= 0 {
		c.ttl = pki.DefaultCATTL
	}
	pub, err := pki.EncodePublicKey(key)
	if err != nil {
		return nil, err
	}
	writes := []struct {
		name string
		data []byte
		mode os.FileMode
	}{
		{"ca_crt.pem", pki.EncodeCert(crt), 0o644},
		{"ca_key.pem", pki.EncodePrivateKey(key), 0o600},
		{"ca_pub.pem", pub, 0o644},
		{"serial", []byte("0002\n"), 0o644}, // CA itself is serial 1
		{"inventory.txt", nil, 0o644},
	}
	for _, w := range writes {
		if err := os.WriteFile(filepath.Join(dir, w.name), w.data, w.mode); err != nil {
			return nil, err
		}
	}
	if err := c.writeCRL(nil); err != nil {
		return nil, err
	}
	c.appendInventory(crt)
	return c, nil
}

// Open loads an existing CA from dir.
func Open(dir string, opts Options) (*CA, error) {
	crtPEM, err := os.ReadFile(filepath.Join(dir, "ca_crt.pem"))
	if err != nil {
		return nil, fmt.Errorf("read CA cert: %w", err)
	}
	keyPEM, err := os.ReadFile(filepath.Join(dir, "ca_key.pem"))
	if err != nil {
		return nil, fmt.Errorf("read CA key: %w", err)
	}
	crt, err := pki.DecodeCert(crtPEM)
	if err != nil {
		return nil, err
	}
	key, err := pki.DecodePrivateKey(keyPEM)
	if err != nil {
		return nil, err
	}
	c := &CA{dir: dir, key: key, crt: crt, ttl: opts.TTL, autosignAll: opts.AutosignAll, allowAltSAN: opts.AllowAltSAN}
	if c.ttl <= 0 {
		c.ttl = pki.DefaultCATTL
	}
	return c, nil
}

// Cert and Key expose the CA material for building the server's TLS config.
func (c *CA) Cert() *x509.Certificate { return c.crt }
func (c *CA) Key() *rsa.PrivateKey    { return c.key }
func (c *CA) CertPEM() []byte         { return pki.EncodeCert(c.crt) }

// SetAutosignAll toggles blanket autosigning at runtime.
func (c *CA) SetAutosignAll(v bool) { c.autosignAll = v }

// --- CSR intake -----------------------------------------------------------

var ErrNotFound = errors.New("not found")

// SubmitCSR stores a pending CSR for name. If the CSR's CN does not match name,
// or a cert/CSR already exists, it errors. When autosign matches, the CSR is
// signed immediately and true is returned.
func (c *CA) SubmitCSR(name string, csrPEM []byte) (signed bool, err error) {
	if !ValidName(name) {
		return false, fmt.Errorf("invalid certname %q", name)
	}
	csr, err := pki.DecodeCSR(csrPEM)
	if err != nil {
		return false, fmt.Errorf("bad CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return false, fmt.Errorf("CSR signature invalid: %w", err)
	}
	if csr.Subject.CommonName != name {
		return false, fmt.Errorf("CSR CN %q does not match certname %q", csr.Subject.CommonName, name)
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if _, err := os.Stat(c.path("signed", name+".pem")); err == nil {
		return false, fmt.Errorf("certificate already signed for %q", name)
	}
	reqPath := c.path("requests", name+".pem")
	if existing, err := os.ReadFile(reqPath); err == nil {
		// A re-submission of the same CSR is idempotent; a different one is
		// rejected so we never silently replace an operator-reviewed request.
		if !bytes.Equal(existing, csrPEM) {
			return false, fmt.Errorf("a different certificate request already exists for %q", name)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	if err := os.WriteFile(reqPath, csrPEM, 0o644); err != nil {
		return false, err
	}
	if c.autosignAll {
		if err := c.signLocked(name, pki.SignOpts{TTL: c.ttl, AllowAltSAN: c.allowAltSAN}); err != nil {
			return false, err
		}
		return true, nil
	}
	return false, nil
}

// GetCSR returns the pending CSR PEM for name.
func (c *CA) GetCSR(name string) ([]byte, error) {
	if !ValidName(name) {
		return nil, ErrNotFound
	}
	b, err := os.ReadFile(c.path("requests", name+".pem"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	return b, err
}

// DeleteCSR removes a pending CSR.
func (c *CA) DeleteCSR(name string) error {
	if !ValidName(name) {
		return ErrNotFound
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	err := os.Remove(c.path("requests", name+".pem"))
	if errors.Is(err, os.ErrNotExist) {
		return ErrNotFound
	}
	return err
}

// GetCert returns a signed cert PEM. name=="ca" returns the CA certificate.
func (c *CA) GetCert(name string) ([]byte, error) {
	if name == "ca" {
		return c.CertPEM(), nil
	}
	if !ValidName(name) {
		return nil, ErrNotFound
	}
	b, err := os.ReadFile(c.path("signed", name+".pem"))
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNotFound
	}
	return b, err
}

// --- signing / revoking ---------------------------------------------------

// Sign issues a cert for a pending CSR. opts.TTL defaults to the CA's ttl.
func (c *CA) Sign(name string, opts pki.SignOpts) error {
	if !ValidName(name) {
		return ErrNotFound
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if opts.TTL <= 0 {
		opts.TTL = c.ttl
	}
	opts.AllowAltSAN = c.allowAltSAN
	return c.signLocked(name, opts)
}

// signLocked must hold c.mu.
func (c *CA) signLocked(name string, opts pki.SignOpts) error {
	csrPEM, err := os.ReadFile(c.path("requests", name+".pem"))
	if errors.Is(err, os.ErrNotExist) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	csr, err := pki.DecodeCSR(csrPEM)
	if err != nil {
		return err
	}
	serial, err := c.nextSerialLocked()
	if err != nil {
		return err
	}
	opts.Serial = serial
	// Copy Puppet trusted-fact extensions from the CSR into the cert, as
	// puppetserver does (registered/private/auth namespaces only).
	opts.ExtraExtensions = append(opts.ExtraExtensions, ppext.AllowedFromCSR(csr.Extensions)...)
	leaf, err := pki.SignCSR(csr, c.crt, c.key, opts)
	if err != nil {
		return err
	}
	if err := os.WriteFile(c.path("signed", name+".pem"), pki.EncodeCert(leaf), 0o644); err != nil {
		return err
	}
	c.appendInventory(leaf)
	_ = os.Remove(c.path("requests", name+".pem")) // request fulfilled
	return nil
}

// Revoke adds name's serial to the CRL. The signed cert file is kept (Puppet
// keeps it too) but the serial is listed as revoked.
func (c *CA) Revoke(name string) error {
	if !ValidName(name) {
		return ErrNotFound
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	b, err := os.ReadFile(c.path("signed", name+".pem"))
	if errors.Is(err, os.ErrNotExist) {
		return ErrNotFound
	} else if err != nil {
		return err
	}
	crt, err := pki.DecodeCert(b)
	if err != nil {
		return err
	}
	revoked := c.readRevokedLocked()
	for _, r := range revoked {
		if r.Serial.Cmp(crt.SerialNumber) == 0 {
			return nil // already revoked
		}
	}
	revoked = append(revoked, pki.RevokedEntry{Serial: crt.SerialNumber, When: time.Now()})
	return c.writeCRL(revoked)
}

// --- status / listing -----------------------------------------------------

// Status returns the certificate_status JSON for one name (signed, requested or
// revoked). Returns ErrNotFound if neither a cert nor a CSR exists.
func (c *CA) Status(name string) (capi.CertStatus, error) {
	if !ValidName(name) {
		return capi.CertStatus{}, ErrNotFound
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.statusLocked(name)
}

// Statuses lists every known certname (signed + pending).
func (c *CA) Statuses() ([]capi.CertStatus, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	names := map[string]bool{}
	for _, sub := range []string{"signed", "requests"} {
		entries, err := os.ReadDir(c.path(sub))
		if err != nil {
			return nil, err // don't report a partial list as success
		}
		for _, e := range entries {
			names[strings.TrimSuffix(e.Name(), ".pem")] = true
		}
	}
	out := make([]capi.CertStatus, 0, len(names))
	for n := range names {
		st, err := c.statusLocked(n)
		if err != nil {
			continue
		}
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func (c *CA) statusLocked(name string) (capi.CertStatus, error) {
	st := capi.CertStatus{Name: name, Fingerprints: map[string]string{}, AuthzExtensions: map[string]string{}}
	if b, err := os.ReadFile(c.path("signed", name+".pem")); err == nil {
		crt, err := pki.DecodeCert(b)
		if err != nil {
			return st, err
		}
		st.State = capi.StateSigned
		for _, r := range c.readRevokedLocked() {
			if r.Serial.Cmp(crt.SerialNumber) == 0 {
				st.State = capi.StateRevoked
			}
		}
		fillCertFields(&st, crt)
		return st, nil
	}
	if b, err := os.ReadFile(c.path("requests", name+".pem")); err == nil {
		csr, err := pki.DecodeCSR(b)
		if err != nil {
			return st, err
		}
		st.State = capi.StateRequested
		st.Fingerprints = pki.Fingerprints(csr.Raw)
		st.Fingerprint = st.Fingerprints["default"]
		st.SubjectAltN = sans(csr.DNSNames, csr.IPAddresses)
		st.DNSAltN = st.SubjectAltN
		st.AuthzExtensions = ppext.AuthExtensions(csr.Extensions)
		return st, nil
	}
	return st, ErrNotFound
}

func fillCertFields(st *capi.CertStatus, crt *x509.Certificate) {
	st.Fingerprints = pki.Fingerprints(crt.Raw)
	st.Fingerprint = st.Fingerprints["default"]
	st.SerialNumber = json.Number(crt.SerialNumber.String())
	st.NotBefore = crt.NotBefore.UTC().Format(time.RFC3339)
	st.NotAfter = crt.NotAfter.UTC().Format(time.RFC3339)
	st.SubjectAltN = sans(crt.DNSNames, crt.IPAddresses)
	st.DNSAltN = st.SubjectAltN
	st.AuthzExtensions = ppext.AuthExtensions(crt.Extensions)
}

func sans(dns []string, ips []net.IP) []string {
	out := []string{}
	for _, d := range dns {
		out = append(out, "DNS:"+d)
	}
	for _, ip := range ips {
		out = append(out, "IP:"+ip.String())
	}
	return out
}

// --- serial / inventory / CRL --------------------------------------------

func (c *CA) nextSerialLocked() (*big.Int, error) {
	b, err := os.ReadFile(c.path("serial"))
	if err != nil {
		return nil, err
	}
	cur, ok := new(big.Int).SetString(strings.TrimSpace(string(b)), 16)
	if !ok {
		return nil, fmt.Errorf("corrupt serial file %q", strings.TrimSpace(string(b)))
	}
	next := new(big.Int).Add(cur, big.NewInt(1))
	if err := os.WriteFile(c.path("serial"), fmt.Appendf(nil, "%04X\n", next), 0o644); err != nil {
		return nil, err
	}
	return cur, nil
}

// appendInventory writes an OpenSSL/Puppet-style inventory line. Best-effort.
func (c *CA) appendInventory(crt *x509.Certificate) {
	line := fmt.Sprintf("0x%04X %s %s /CN=%s\n",
		crt.SerialNumber,
		puppetTime(crt.NotBefore), puppetTime(crt.NotAfter),
		crt.Subject.CommonName)
	f, err := os.OpenFile(c.path("inventory.txt"), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return
	}
	defer func() { _ = f.Close() }()
	_, _ = f.WriteString(line)
}

func puppetTime(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05") + "UTC" }

// readRevokedLocked parses the current CRL back into serial entries so we can
// append without losing prior revocations.
func (c *CA) readRevokedLocked() []pki.RevokedEntry {
	b, err := os.ReadFile(c.path("ca_crl.pem"))
	if err != nil {
		return nil
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil
	}
	crl, err := x509.ParseRevocationList(blk.Bytes)
	if err != nil {
		return nil
	}
	out := make([]pki.RevokedEntry, 0, len(crl.RevokedCertificateEntries))
	for _, e := range crl.RevokedCertificateEntries {
		out = append(out, pki.RevokedEntry{Serial: e.SerialNumber, When: e.RevocationTime})
	}
	return out
}

func (c *CA) writeCRL(revoked []pki.RevokedEntry) error {
	crlPEM, err := pki.CreateCRL(c.crt, c.key, revoked, 0)
	if err != nil {
		return err
	}
	return os.WriteFile(c.path("ca_crl.pem"), crlPEM, 0o644)
}

// CRL returns the current CRL PEM.
func (c *CA) CRL() ([]byte, error) { return os.ReadFile(c.path("ca_crl.pem")) }

// Clean removes a host's signed cert and any pending CSR (DELETE
// certificate_status). It does not revoke; call Revoke first if needed.
func (c *CA) Clean(name string) error {
	if !ValidName(name) {
		return ErrNotFound
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	e1 := os.Remove(c.path("signed", name+".pem"))
	e2 := os.Remove(c.path("requests", name+".pem"))
	if errors.Is(e1, os.ErrNotExist) && errors.Is(e2, os.ErrNotExist) {
		return ErrNotFound
	}
	if e1 != nil && !errors.Is(e1, os.ErrNotExist) {
		return e1 // surface real failures (e.g. permissions) instead of "cleaned"
	}
	if e2 != nil && !errors.Is(e2, os.ErrNotExist) {
		return e2
	}
	return nil
}

// ServerTLSCert loads or issues the server's own leaf cert (CN=names[0], SANs
// = names) signed by this CA, and returns it as a chain (leaf + CA) ready for a
// tls.Config. Persisted as server_crt.pem / server_key.pem in the cadir.
func (c *CA) ServerTLSCert(names []string) (tls.Certificate, error) {
	if len(names) == 0 {
		return tls.Certificate{}, errors.New("at least one server TLS name is required")
	}
	crtPath, keyPath := c.path("server_crt.pem"), c.path("server_key.pem")
	if cb, err := os.ReadFile(crtPath); err == nil {
		if kb, err := os.ReadFile(keyPath); err == nil {
			leaf, err := pki.DecodeCert(cb)
			if err != nil {
				return tls.Certificate{}, err
			}
			key, err := pki.DecodePrivateKey(kb)
			if err != nil {
				return tls.Certificate{}, err
			}
			return tls.Certificate{Certificate: [][]byte{leaf.Raw, c.crt.Raw}, PrivateKey: key, Leaf: leaf}, nil
		}
	}
	key, err := pki.GenerateKey(0)
	if err != nil {
		return tls.Certificate{}, err
	}
	csrPEM, err := pki.CreateCSR(key, names[0], names, nil)
	if err != nil {
		return tls.Certificate{}, err
	}
	csr, err := pki.DecodeCSR(csrPEM)
	if err != nil {
		return tls.Certificate{}, err
	}
	c.mu.Lock()
	serial, err := c.nextSerialLocked()
	c.mu.Unlock()
	if err != nil {
		return tls.Certificate{}, err
	}
	leaf, err := pki.SignCSR(csr, c.crt, c.key, pki.SignOpts{Serial: serial, TTL: c.ttl, AllowAltSAN: true})
	if err != nil {
		return tls.Certificate{}, err
	}
	if err := os.WriteFile(crtPath, pki.EncodeCert(leaf), 0o644); err != nil {
		return tls.Certificate{}, err
	}
	if err := os.WriteFile(keyPath, pki.EncodePrivateKey(key), 0o600); err != nil {
		return tls.Certificate{}, err
	}
	c.appendInventory(leaf)
	return tls.Certificate{Certificate: [][]byte{leaf.Raw, c.crt.Raw}, PrivateKey: key, Leaf: leaf}, nil
}
