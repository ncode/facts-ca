// Package agent is the enrollment half of facts-ca as a library. Enroll obtains
// a CA-signed certificate over the Puppet CA v1 protocol and returns an Identity
// that yields inbound and outbound mTLS — so a service gets a mutually
// authenticated transport in a few lines:
//
//	id, _ := agent.Enroll(ctx, agent.Config{
//	    Server: "ca.internal:8140", Certname: "payments-api.prod",
//	    CAFingerprint: pinned,
//	})
//	srv := &http.Server{Addr: ":8443", TLSConfig: id.ServerTLSConfig(), Handler: mux}
//	out := id.HTTPClient() // calls to mesh peers are mutually authenticated
//
// Enrollment is one-shot (renewal-ready via the Identity callbacks), never
// prints (it returns errors and takes an optional *slog.Logger), trusts a CA
// only via an explicit pin or opt-in TrustOnFirstUse, and stores nothing on disk
// unless Config.Dir is set.
package agent

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ncode/facts-ca/internal/capi"
	"github.com/ncode/facts-ca/internal/ppext"
	"github.com/ncode/facts-ca/internal/ssldir"
	"github.com/ncode/facts-ca/pki"
)

// Config controls a single Enroll call.
type Config struct {
	Server      string            // CA host:port (":8140" is appended if no port)
	Certname    string            // identity; defaults to the host FQDN
	Dir         string            // ssldir path; empty => ephemeral, in-memory only
	KeyBits     int               // RSA key size; <=0 => pki.DefaultKeyBits (4096)
	DNSAltNames []string          // subjectAltNames to request
	Extensions  map[string]string // Puppet trusted facts: pp_role, pp_uuid, ... (or dotted OIDs)

	// Trust: pin the CA (CACert PEM or CAFingerprint), or opt into TrustOnFirstUse.
	// Enroll never trusts a fetched CA silently.
	CACert          []byte // pinned CA certificate PEM
	CAFingerprint   string // accept a fetched CA only if its SHA256 fingerprint matches
	TrustOnFirstUse bool   // explicitly fetch-and-trust the CA on first contact

	WaitForCert time.Duration // how long to wait for signing; 0 => single attempt
	Logger      *slog.Logger  // optional; nil => no logging (the library never prints)
}

func (c Config) logger() *slog.Logger {
	if c.Logger != nil {
		return c.Logger
	}
	return slog.New(slog.DiscardHandler)
}

// Enroll obtains a CA-signed certificate for the configured certname and returns
// a usable mTLS Identity. With Config.Dir set it reads/writes a Puppet ssldir and
// reuses an existing identity; with Dir empty it is ephemeral and in-memory.
func Enroll(ctx context.Context, cfg Config) (*Identity, error) {
	e, err := newEnroller(cfg)
	if err != nil {
		return nil, err
	}
	return e.run(ctx)
}

type enroller struct {
	cfg      Config
	server   string // host:port
	certname string
	ssl      *ssldir.SSLDir // nil => ephemeral
	log      *slog.Logger
}

func newEnroller(cfg Config) (*enroller, error) {
	server := cfg.Server
	if server == "" {
		return nil, errors.New("agent.Config.Server is required")
	}
	if _, _, err := net.SplitHostPort(server); err != nil {
		server = net.JoinHostPort(server, "8140") // default Puppet port
	}
	certname := cfg.Certname
	if certname == "" {
		certname = defaultCertname()
	}
	if !capi.ValidCertname(certname) {
		return nil, fmt.Errorf("invalid certname %q (lowercase letters, digits, .-_ only; no path separators)", certname)
	}
	e := &enroller{cfg: cfg, server: server, certname: certname, log: cfg.logger()}
	if cfg.Dir != "" {
		e.ssl = ssldir.New(cfg.Dir, certname)
	}
	return e, nil
}

func (e *enroller) run(ctx context.Context) (*Identity, error) {
	keyBits := e.cfg.KeyBits
	if keyBits <= 0 {
		keyBits = pki.DefaultKeyBits
	}
	if keyBits < 2048 {
		return nil, fmt.Errorf("agent.Config.KeyBits must be at least 2048 (got %d)", keyBits)
	}

	// Fast path: a fully provisioned ssldir loads with no network — re-runs and
	// the commands that only need the already-stored identity (mtls, ca admin).
	if e.ssl != nil {
		if id, ok, err := e.loadFromDisk(); err != nil {
			return nil, err
		} else if ok {
			return id, nil
		}
		if err := e.ssl.Ensure(); err != nil {
			return nil, err
		}
	}

	caPEM, err := e.obtainCA(ctx)
	if err != nil {
		return nil, fmt.Errorf("obtain CA: %w", err)
	}
	client, err := e.verifiedClient(caPEM, nil)
	if err != nil {
		return nil, err
	}

	// Best-effort CRL so a disk ssldir matches a real agent's. Only persist a
	// real 200 body — never an error page.
	if e.ssl != nil {
		if crl, code, err := httpGET(ctx, client, e.caURL("/certificate_revocation_list/ca")); err == nil && code == http.StatusOK {
			_ = e.ssl.WriteCRL(crl)
		}
	}

	key, err := e.loadOrCreateKey(keyBits)
	if err != nil {
		return nil, err
	}

	// Already signed (issued out of band, or signed but not yet stored locally)?
	if body, code, _ := httpGET(ctx, client, e.caURL("/certificate/"+e.certname)); code == http.StatusOK {
		return e.adopt(body, caPEM, key)
	}

	exts, err := ppext.BuildExtensions(e.cfg.Extensions)
	if err != nil {
		return nil, fmt.Errorf("extension requests: %w", err)
	}
	csrPEM, err := pki.CreateCSR(key, e.certname, e.cfg.DNSAltNames, exts)
	if err != nil {
		return nil, err
	}
	if e.ssl != nil {
		if err := e.ssl.WriteCSR(csrPEM); err != nil {
			return nil, err
		}
	}
	e.log.Info("submitting CSR", "certname", e.certname, "server", e.server)
	if _, code, err := httpPUT(ctx, client, e.caURL("/certificate_request/"+e.certname), csrPEM); err != nil {
		return nil, fmt.Errorf("submit CSR: %w", err)
	} else if code != http.StatusOK {
		return nil, fmt.Errorf("submit CSR: server returned %d", code)
	}

	cert, err := e.pollForCert(ctx, client)
	if err != nil {
		return nil, err
	}
	return e.adopt(cert, caPEM, key)
}

// loadFromDisk returns a stored identity when the ssldir already holds a CA, a
// matching key and a valid cert; ok=false means "not provisioned, go enroll".
func (e *enroller) loadFromDisk() (id *Identity, ok bool, err error) {
	caPEM, err := e.ssl.ReadCACert()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("read stored CA certificate: %w", err)
	}
	if len(caPEM) == 0 || !e.ssl.HasCert() || !e.ssl.HasKey() {
		return nil, false, nil
	}
	if err := validatePinnedCA(caPEM, e.cfg); err != nil {
		return nil, false, err // stored CA contradicts an explicit pin
	}
	certPEM, err := os.ReadFile(e.ssl.CertPath())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("read stored certificate: %w", err)
	}
	keyPEM, err := os.ReadFile(e.ssl.PrivateKeyPath())
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, false, nil
		}
		return nil, false, fmt.Errorf("read stored private key: %w", err)
	}
	key, err := pki.DecodePrivateKey(keyPEM)
	if err != nil {
		return nil, false, err
	}
	if err := validateIssuedCert(certPEM, caPEM, e.certname, key); err != nil {
		return nil, false, err // a corrupt/mismatched store is an error, not a silent re-enroll
	}
	leaf, err := pki.DecodeCert(certPEM)
	if err != nil {
		return nil, false, err
	}
	id, err = newIdentity(e.certname, leaf, key, caPEM)
	if err != nil {
		return nil, false, err
	}
	return id, true, nil
}

// adopt validates a fetched certificate, persists it (when on disk), and builds
// the Identity.
func (e *enroller) adopt(certPEM, caPEM []byte, key *rsa.PrivateKey) (*Identity, error) {
	if err := validateIssuedCert(certPEM, caPEM, e.certname, key); err != nil {
		return nil, err
	}
	if e.ssl != nil {
		if err := e.ssl.WriteCert(certPEM); err != nil {
			return nil, err
		}
	}
	leaf, err := pki.DecodeCert(certPEM)
	if err != nil {
		return nil, err
	}
	return newIdentity(e.certname, leaf, key, caPEM)
}

// obtainCA returns the CA PEM to trust: a disk-pinned copy, a configured pin,
// or a fetched CA validated by fingerprint / accepted under TrustOnFirstUse.
func (e *enroller) obtainCA(ctx context.Context) ([]byte, error) {
	if e.ssl != nil {
		if b, err := e.ssl.ReadCACert(); err == nil && len(b) > 0 {
			if err := validatePinnedCA(b, e.cfg); err != nil {
				return nil, err // a stored CA must still satisfy an explicit pin
			}
			return b, nil // already pinned on a previous run
		}
	}
	var caPEM []byte
	switch {
	case len(e.cfg.CACert) > 0:
		crt, err := pki.DecodeCert(e.cfg.CACert)
		if err != nil {
			return nil, fmt.Errorf("pinned CACert is not a certificate: %w", err)
		}
		if e.cfg.CAFingerprint != "" { // both pins set: they must agree
			if got := pki.Fingerprints(crt.Raw)["SHA256"]; !fingerprintEqual(got, e.cfg.CAFingerprint) {
				return nil, fmt.Errorf("configured CACert does not match CAFingerprint: CACert is %s", got)
			}
		}
		caPEM = e.cfg.CACert
	case e.cfg.CAFingerprint != "" || e.cfg.TrustOnFirstUse:
		body, err := e.tofuFetchCA(ctx)
		if err != nil {
			return nil, err
		}
		crt, err := pki.DecodeCert(body)
		if err != nil {
			return nil, fmt.Errorf("CA response is not a certificate: %w", err)
		}
		if e.cfg.CAFingerprint != "" {
			got := pki.Fingerprints(crt.Raw)["SHA256"]
			if !fingerprintEqual(got, e.cfg.CAFingerprint) {
				return nil, fmt.Errorf("CA fingerprint mismatch: server presented %s", got)
			}
		}
		caPEM = body
	default:
		return nil, errors.New("no CA trust configured: set CACert, CAFingerprint, or TrustOnFirstUse")
	}
	if e.ssl != nil {
		if err := e.ssl.WriteCACert(caPEM); err != nil {
			return nil, err
		}
		e.log.Info("pinned CA certificate", "path", e.ssl.CACertPath())
	}
	return caPEM, nil
}

// tofuFetchCA fetches /certificate/ca without verifying the server, the way a
// fresh Puppet agent bootstraps. The result is only trusted after the caller's
// fingerprint check or explicit TrustOnFirstUse opt-in.
func (e *enroller) tofuFetchCA(ctx context.Context) ([]byte, error) {
	tofu := &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, // ponytail: unverified CA fetch; trust is decided by the caller's pin/TOFU
	}
	body, code, err := httpGET(ctx, tofu, e.caURL("/certificate/ca"))
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("CA fetch returned %d", code)
	}
	return body, nil
}

func (e *enroller) pollForCert(ctx context.Context, client *http.Client) ([]byte, error) {
	wait := e.cfg.WaitForCert
	interval := 10 * time.Second
	if wait > 0 && wait < interval {
		interval = wait
	}
	deadline := time.Now().Add(wait)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		body, code, err := httpGET(ctx, client, e.caURL("/certificate/"+e.certname))
		if err == nil && code == http.StatusOK {
			return body, nil
		}
		if wait <= 0 {
			return nil, errors.New("certificate not yet signed (run again or have the CA sign it)")
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			return nil, fmt.Errorf("gave up waiting for certificate after %s", wait)
		}
		sleep := min(interval, remaining) // never sleep past the deadline
		e.log.Info("waiting for certificate to be signed", "retry_in", sleep.String())
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(sleep):
		}
	}
}

func (e *enroller) loadOrCreateKey(bits int) (*rsa.PrivateKey, error) {
	if e.ssl != nil {
		return e.ssl.LoadOrCreateKey(bits)
	}
	return pki.GenerateKey(bits)
}

// verifiedClient trusts caPEM and verifies the server hostname; an optional
// client cert enables mTLS.
func (e *enroller) verifiedClient(caPEM []byte, clientCert *tls.Certificate) (*http.Client, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("could not parse CA certificate")
	}
	cfg := &tls.Config{RootCAs: pool, ServerName: e.host(), MinVersion: tls.VersionTLS12}
	if clientCert != nil {
		cfg.Certificates = []tls.Certificate{*clientCert}
	}
	return &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg}}, nil
}

func (e *enroller) baseURL() string { return "https://" + e.server + capi.Base }
func (e *enroller) host() string    { h, _, _ := net.SplitHostPort(e.server); return h }

// caURL builds an agent CA-API URL with the environment query a real Puppet
// agent sends (the CA ignores it, but some puppetserver versions expect it).
func (e *enroller) caURL(path string) string { return e.baseURL() + path + "?environment=production" }

// validateIssuedCert checks a fetched cert before adoption: valid PEM that
// chains to the pinned CA, carries the requested certname, and matches our key.
func validateIssuedCert(certPEM, caPEM []byte, certname string, key *rsa.PrivateKey) error {
	crt, err := pki.DecodeCert(certPEM)
	if err != nil {
		return fmt.Errorf("issued cert is not valid PEM: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return errors.New("cannot parse pinned CA")
	}
	if _, err := crt.Verify(x509.VerifyOptions{Roots: pool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}); err != nil {
		return fmt.Errorf("issued cert does not chain to pinned CA: %w", err)
	}
	if crt.Subject.CommonName != certname {
		return fmt.Errorf("issued cert CN %q does not match requested certname %q", crt.Subject.CommonName, certname)
	}
	pub, ok := crt.PublicKey.(*rsa.PublicKey)
	if !ok || pub.N.Cmp(key.N) != 0 || pub.E != key.E {
		return errors.New("issued cert public key does not match local private key")
	}
	return nil
}

// validatePinnedCA fails if caPEM (a stored or fetched CA) contradicts an
// explicit Config pin. With no pin it is a no-op, so TrustOnFirstUse and the
// disk-reuse paths are unaffected.
func validatePinnedCA(caPEM []byte, cfg Config) error {
	if len(cfg.CACert) > 0 {
		stored, err := pki.DecodeCert(caPEM)
		if err != nil {
			return fmt.Errorf("stored CA certificate is invalid: %w", err)
		}
		pinned, err := pki.DecodeCert(cfg.CACert)
		if err != nil {
			return fmt.Errorf("configured CACert is not a certificate: %w", err)
		}
		if !bytes.Equal(stored.Raw, pinned.Raw) {
			return errors.New("stored CA certificate does not match configured CACert")
		}
	}
	if cfg.CAFingerprint != "" {
		crt, err := pki.DecodeCert(caPEM)
		if err != nil {
			return fmt.Errorf("stored CA certificate is invalid: %w", err)
		}
		if got := pki.Fingerprints(crt.Raw)["SHA256"]; !fingerprintEqual(got, cfg.CAFingerprint) {
			return fmt.Errorf("stored CA fingerprint mismatch: stored CA is %s", got)
		}
	}
	return nil
}

// Load returns the identity already stored in dir for certname, with no network
// and no disk mutation. It errors if the ssldir is not fully provisioned (CA +
// key + valid cert), which is what the mtls/admin commands want: use a
// previously bootstrapped identity, or fail rather than start enrolling.
func Load(dir, certname string) (*Identity, error) {
	if dir == "" {
		return nil, errors.New("agent.Load requires a dir")
	}
	if certname == "" {
		certname = defaultCertname()
	}
	if !capi.ValidCertname(certname) {
		return nil, fmt.Errorf("invalid certname %q", certname)
	}
	e := &enroller{certname: certname, ssl: ssldir.New(dir, certname), log: slog.New(slog.DiscardHandler)}
	id, ok, err := e.loadFromDisk()
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("no bootstrapped identity for %q in %s (run bootstrap first)", certname, dir)
	}
	return id, nil
}

func defaultCertname() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "agent"
	}
	return h
}

// fingerprintEqual compares two SHA256 fingerprints ignoring case and colons, so
// a pin given as "AB:CD:..." or "abcd..." both match.
func fingerprintEqual(a, b string) bool {
	norm := func(s string) string { return strings.ToLower(strings.ReplaceAll(s, ":", "")) }
	return norm(a) == norm(b)
}

// --- tiny HTTP helpers ----------------------------------------------------

func httpGET(ctx context.Context, c *http.Client, url string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", capi.PEMContentType)
	return do(c, req)
}

func httpPUT(ctx context.Context, c *http.Client, url string, body []byte) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, url, bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", capi.PEMContentType)
	return do(c, req)
}

const maxResponseBytes = 4 << 20 // 4 MiB — generous for any PEM cert/CSR/CRL

func do(c *http.Client, req *http.Request) ([]byte, int, error) {
	resp, err := c.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	// Read one extra byte so an oversized body is an explicit error, not a
	// silent truncation (a truncated CRL must never be written to disk).
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	if len(b) > maxResponseBytes {
		return nil, resp.StatusCode, fmt.Errorf("response body exceeds %d bytes", maxResponseBytes)
	}
	return b, resp.StatusCode, nil
}
