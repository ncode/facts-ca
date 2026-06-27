package agent

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/http"
	"sync"
	"time"
)

// Identity is a CA-signed mTLS identity: the issued leaf certificate, its key,
// and the pinned CA. It yields ready-to-use client and server TLS, so a consumer
// gets inbound + outbound mutual TLS with no Puppet-protocol knowledge.
//
// The TLS configs read the current certificate through Get(Client)Certificate
// callbacks, so a future renewer can swap the leaf in place (via the guarded
// setCert) without invalidating configs already handed to http.Server/Client.
type Identity struct {
	certname string

	mu     sync.RWMutex
	cert   tls.Certificate
	caPEM  []byte
	caPool *x509.CertPool
}

func newIdentity(certname string, leaf *x509.Certificate, key *rsa.PrivateKey, caPEM []byte) (*Identity, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("cannot parse CA PEM")
	}
	return &Identity{
		certname: certname,
		cert:     tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: key, Leaf: leaf},
		caPEM:    append([]byte(nil), caPEM...), // own a copy; the caller's slice can't mutate us
		caPool:   pool,
	}, nil
}

func (i *Identity) current() tls.Certificate {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.cert
}

// setCert swaps the live certificate; reserved for a future renewer. Callbacks
// in the TLS configs pick it up on the next handshake.
func (i *Identity) setCert(c tls.Certificate) {
	i.mu.Lock()
	defer i.mu.Unlock()
	i.cert = c
}

// Certname returns the identity's certname (its certificate CN).
func (i *Identity) Certname() string { return i.certname }

// Certificate returns the current leaf certificate + key.
func (i *Identity) Certificate() tls.Certificate { return i.current() }

// CAPool returns a pool holding the pinned CA, for verifying peers. It is a copy
// so a caller can't alter what this identity's TLS configs trust.
func (i *Identity) CAPool() *x509.CertPool { return i.caPool.Clone() }

// CACertPEM returns a copy of the pinned CA certificate as PEM.
func (i *Identity) CACertPEM() []byte { return append([]byte(nil), i.caPEM...) }

// ClientTLSConfig returns an outbound mTLS config: it presents this identity's
// certificate and verifies the server against the pinned CA. serverName is the
// expected server hostname ("" lets crypto/tls use the dialed host).
func (i *Identity) ClientTLSConfig(serverName string) *tls.Config {
	return &tls.Config{
		RootCAs:    i.caPool.Clone(), // a returned config must not be able to widen our trust
		ServerName: serverName,
		MinVersion: tls.VersionTLS12,
		GetClientCertificate: func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			c := i.current()
			return &c, nil
		},
	}
}

// ServerTLSConfig returns an inbound mTLS config: it presents this identity's
// certificate and requires every client to present a CA-signed certificate
// (RequireAndVerifyClientCert).
func (i *Identity) ServerTLSConfig() *tls.Config {
	return &tls.Config{
		ClientCAs:  i.caPool.Clone(), // a returned config must not be able to widen our trust
		ClientAuth: tls.RequireAndVerifyClientCert,
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			c := i.current()
			return &c, nil
		},
	}
}

// HTTPClient returns an *http.Client that authenticates with this identity and
// verifies servers against the pinned CA (verifying the dialed hostname). It
// clones http.DefaultTransport so proxy support, dial/handshake timeouts,
// keep-alives and HTTP/2 match Go's default client.
func (i *Identity) HTTPClient() *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = i.ClientTLSConfig("")
	return &http.Client{Timeout: 30 * time.Second, Transport: tr}
}

// Listener returns a TLS listener on addr that requires CA-signed client certs.
func (i *Identity) Listener(addr string) (net.Listener, error) {
	return tls.Listen("tcp", addr, i.ServerTLSConfig())
}
