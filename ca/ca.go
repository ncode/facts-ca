// Package ca is the embeddable Puppet-compatible certificate authority — the
// "CA half" of facts-ca as a library. A consumer can run a standalone CA or
// mount its Puppet CA v1 routes on an existing server, in a few lines and with
// no Puppet-protocol knowledge:
//
//	c, _ := ca.Open(ca.Options{Dir: "/var/lib/myca"})
//	mux.Handle("/puppet-ca/v1/", c.Handler())
//
// The on-disk cadir, wire protocol and signing behavior match puppetserver, so
// real Puppet agents (and facts-ca-cli) enroll against it unchanged. The CA is
// disk-backed and single-writer (a per-process mutex guards the cadir).
package ca

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ncode/facts-ca/internal/capi"
	"github.com/ncode/facts-ca/internal/castore"
	"github.com/ncode/facts-ca/pki"
)

// Options configure Init and Open.
type Options struct {
	Dir         string        // cadir (durable; required) — puppetserver layout
	CAName      string        // CA subject name; defaults to the first Hostname, then the host FQDN
	Hostnames   []string      // FQDN(s) for the server's own TLS leaf; defaults to the host FQDN
	TTL         time.Duration // issued-cert lifetime; 0 => pki.DefaultCATTL
	AutosignAll bool          // sign every valid incoming CSR (insecure)
	AllowAltSAN bool          // honor agent-requested SANs; default false matches puppetserver
	Logger      *slog.Logger  // optional; nil => no logging (the library never prints)
}

// CA is a loaded certificate authority. It wraps the on-disk cadir store and
// adds the Puppet CA v1 HTTP surface and TLS serving.
type CA struct {
	store     *castore.CA
	hostnames []string
	log       *slog.Logger
}

func (o Options) storeOpts() castore.Options {
	return castore.Options{TTL: o.TTL, AutosignAll: o.AutosignAll, AllowAltSAN: o.AllowAltSAN}
}

func (o Options) logger() *slog.Logger {
	if o.Logger != nil {
		return o.Logger
	}
	return slog.New(slog.DiscardHandler)
}

func (o Options) hostnames() []string {
	out := make([]string, 0, len(o.Hostnames))
	for _, h := range o.Hostnames {
		if h = strings.TrimSpace(h); h != "" {
			out = append(out, h)
		}
	}
	if len(out) == 0 {
		return []string{defaultHostname()}
	}
	return out
}

// Init creates a fresh CA in Options.Dir, failing if one already exists.
func Init(o Options) (*CA, error) {
	if o.Dir == "" {
		return nil, errors.New("ca.Options.Dir is required")
	}
	name := o.CAName
	if name == "" {
		name = o.hostnames()[0]
	}
	store, err := castore.Init(o.Dir, name, 0, o.storeOpts())
	if err != nil {
		return nil, err
	}
	return &CA{store: store, hostnames: o.hostnames(), log: o.logger()}, nil
}

// Open loads an existing CA from Options.Dir.
func Open(o Options) (*CA, error) {
	if o.Dir == "" {
		return nil, errors.New("ca.Options.Dir is required")
	}
	store, err := castore.Open(o.Dir, o.storeOpts())
	if err != nil {
		return nil, err
	}
	return &CA{store: store, hostnames: o.hostnames(), log: o.logger()}, nil
}

// IsNotExist reports whether err from Open means there is no CA at the dir yet,
// so a caller can decide whether to Init. It papers over the platform-specific
// "no such file" wording the same way the server binary used to.
func IsNotExist(err error) bool {
	return errors.Is(err, os.ErrNotExist) || (err != nil && strings.Contains(err.Error(), "no such file"))
}

// CACertPEM returns the CA certificate as PEM (what agents pin).
func (c *CA) CACertPEM() []byte { return c.store.CertPEM() }

// Cert returns the CA certificate as a fresh parse, so a caller mutating the
// result can't corrupt the CA's own state.
func (c *CA) Cert() *x509.Certificate {
	if crt := c.store.Cert(); crt != nil {
		if clone, err := x509.ParseCertificate(crt.Raw); err == nil {
			return clone
		}
	}
	return nil
}

// --- admin operations -----------------------------------------------------

// Sign issues a certificate for a pending CSR. opts.TTL defaults to the CA's TTL.
func (c *CA) Sign(name string, opts pki.SignOpts) error { return c.store.Sign(name, opts) }

// Revoke adds name's serial to the CRL.
func (c *CA) Revoke(name string) error { return c.store.Revoke(name) }

// Clean removes a host's signed cert and any pending CSR. It does not revoke;
// call Revoke first if you also want the serial on the CRL.
func (c *CA) Clean(name string) error { return c.store.Clean(name) }

// Status returns the certificate status for one certname.
func (c *CA) Status(name string) (Status, error) {
	st, err := c.store.Status(name)
	return statusFromInternal(st), err
}

// Statuses lists every known certname (signed + pending).
func (c *CA) Statuses() ([]Status, error) {
	list, err := c.store.Statuses()
	if err != nil {
		return nil, err
	}
	out := make([]Status, len(list))
	for i, s := range list {
		out[i] = statusFromInternal(s)
	}
	return out, nil
}

// --- TLS / serving --------------------------------------------------------

// ServerTLSConfig returns a *tls.Config for serving the CA over HTTPS: the
// CA-signed leaf (CN/SANs = Options.Hostnames), ClientCAs set to the CA, and
// verify-client-if-given so a fresh agent can bootstrap without a certificate
// while admin routes separately require one. It issues/loads the server leaf
// (server_crt.pem) in the cadir on first use.
func (c *CA) ServerTLSConfig() (*tls.Config, error) {
	leaf, err := c.store.ServerTLSCert(c.hostnames) // store serializes the one-time mint
	if err != nil {
		return nil, fmt.Errorf("server cert: %w", err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(c.store.Cert())
	return &tls.Config{
		Certificates: []tls.Certificate{leaf},
		ClientCAs:    pool,
		ClientAuth:   tls.VerifyClientCertIfGiven,
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// ListenAndServe serves the Puppet CA v1 API over mTLS on addr until error.
func (c *CA) ListenAndServe(addr string) error {
	cfg, err := c.ServerTLSConfig()
	if err != nil {
		return err
	}
	srv := &http.Server{
		Addr:              addr,
		Handler:           c.Handler(),
		TLSConfig:         cfg,
		ReadHeaderTimeout: 10 * time.Second,
	}
	return srv.ListenAndServeTLS("", "")
}

func defaultHostname() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "localhost"
	}
	return h
}

// stateSigned/stateRevoked re-export the internal wire constants so callers of
// DesiredState don't need the internal package.
const (
	StateSigned  = capi.StateSigned
	StateRevoked = capi.StateRevoked
)
