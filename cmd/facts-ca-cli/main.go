// facts-ca-cli is a Go port of the Puppet agent's CA bootstrap. It fetches the
// CA cert (trust-on-first-use, like a fresh Puppet agent), generates a key and
// CSR, submits it, polls until the cert is signed, and stores everything in a
// Puppet-compatible ssldir — then can open an mTLS connection with the result.
//
// Usage:
//
//	facts-ca-cli bootstrap --server ca.example.com:8140 [--certname host.fqdn] [--ssldir DIR]
//	                       [--waitforcert 2m] [--dns-alt-names a,b] [--onetime]
//	facts-ca-cli mtls      --server ca.example.com:8140 --url https://svc/path
//	facts-ca-cli ca list|sign <name>|revoke <name> --server ca.example.com:8140
package main

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/ncode/facts-ca/internal/capi"
	"github.com/ncode/facts-ca/internal/pki"
	"github.com/ncode/facts-ca/internal/ppext"
	"github.com/ncode/facts-ca/internal/ssldir"
	"github.com/ncode/facts-ca/internal/version"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "bootstrap":
		err = cmdBootstrap(os.Args[2:])
	case "mtls":
		err = cmdMTLS(os.Args[2:])
	case "ca":
		err = cmdCA(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Println(version.Version)
		return
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n", os.Args[1])
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `facts-ca-cli — Puppet-compatible CA agent

  bootstrap  --server H:8140 [--certname N] [--ssldir D] [--waitforcert 2m] [--onetime]
             [--dns-alt-names a,b] [--keylength 4096]
             [--ext pp_role=web --ext pp_uuid=...] [--csr-attributes csr_attributes.yaml]
  mtls       --server H:8140 --url https://svc/path
  ca list | ca sign <name> | ca revoke <name>   --server H:8140

The ssldir defaults to ./ssl and the certname to this host's FQDN.
Extended attributes: --ext takes a Puppet short name (pp_role, pp_uuid, ...) or a
dotted OID under 1.3.6.1.4.1.34380.1.*, and is repeatable; --csr-attributes reads
a Puppet csr_attributes.yaml. The CA copies these into the issued certificate.
`)
	os.Exit(2)
}

// agent bundles the resolved config and ssldir for a run.
type agent struct {
	server   string // host:port
	certname string
	ssl      *ssldir.SSLDir
}

// flags shared by bootstrap/mtls/ca, parsed by hand to stay dependency-free.
func parseCommon(args []string) (map[string]string, []string) {
	opts := map[string]string{}
	var positional []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		if len(a) > 2 && a[:2] == "--" {
			key := a[2:]
			if k, v, found := strings.Cut(key, "="); found {
				opts[k] = v
				continue
			}
			// boolean flags
			if key == "onetime" {
				opts[key] = "true"
				continue
			}
			if i+1 < len(args) {
				opts[key] = args[i+1]
				i++
			} else {
				opts[key] = "true"
			}
		} else {
			positional = append(positional, a)
		}
	}
	return opts, positional
}

func newAgent(opts map[string]string) (*agent, error) {
	server := opts["server"]
	if server == "" {
		return nil, errors.New("--server H:8140 is required")
	}
	if _, _, err := net.SplitHostPort(server); err != nil {
		server = net.JoinHostPort(server, "8140") // default Puppet port
	}
	dir := opts["ssldir"]
	if dir == "" {
		dir = "./ssl"
	}
	certname := opts["certname"]
	if certname == "" {
		// Reuse an already-bootstrapped identity if there is exactly one, so
		// mtls/ca commands don't need --certname repeated. Falls back to FQDN.
		certname = discoverCertname(dir)
	}
	if certname == "" {
		certname = defaultCertname()
	}
	if !capi.ValidCertname(certname) {
		return nil, fmt.Errorf("invalid certname %q (lowercase letters, digits, .-_ only; no path separators)", certname)
	}
	return &agent{server: server, certname: certname, ssl: ssldir.New(dir, certname)}, nil
}

// discoverCertname returns the single non-CA leaf cert basename in <dir>/certs,
// or "" if there are zero or several.
func discoverCertname(dir string) string {
	entries, err := os.ReadDir(filepath.Join(dir, "certs"))
	if err != nil {
		return ""
	}
	var found string
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || n == "ca.pem" || !strings.HasSuffix(n, ".pem") {
			continue
		}
		if found != "" {
			return "" // ambiguous; require explicit --certname
		}
		found = strings.TrimSuffix(n, ".pem")
	}
	return found
}

func (a *agent) baseURL() string { return "https://" + a.server + capi.Base }
func (a *agent) host() string    { h, _, _ := net.SplitHostPort(a.server); return h }

// caURL builds an agent CA-API URL with the environment query a real Puppet
// agent sends (the CA ignores it, but some puppetserver versions expect it).
func (a *agent) caURL(path string) string { return a.baseURL() + path + "?environment=production" }

// --- bootstrap ------------------------------------------------------------

func cmdBootstrap(args []string) error {
	opts, _ := parseCommon(args)
	a, err := newAgent(opts)
	if err != nil {
		return err
	}
	if err := a.ssl.Ensure(); err != nil {
		return err
	}
	keylen := atoiOr(opts["keylength"], pki.DefaultKeyBits)
	if keylen < 2048 || keylen > 8192 {
		return fmt.Errorf("--keylength must be between 2048 and 8192 (got %d)", keylen)
	}
	wait := durationOr(opts["waitforcert"], 2*time.Minute)
	if opts["onetime"] == "true" {
		wait = 0
	}

	caPEM, err := a.ensureCA()
	if err != nil {
		return fmt.Errorf("fetch CA: %w", err)
	}
	verified, err := a.verifiedClient(caPEM, nil)
	if err != nil {
		return err
	}

	// Best-effort CRL so the ssldir matches a real agent's.
	if crl, _, err := httpGET(verified, a.caURL("/certificate_revocation_list/ca")); err == nil {
		_ = a.ssl.WriteCRL(crl)
	}

	key, err := a.ssl.LoadOrCreateKey(keylen)
	if err != nil {
		return err
	}

	// Already signed? (e.g. re-run, or cert issued out of band.)
	if body, code, _ := httpGET(verified, a.caURL("/certificate/"+a.certname)); code == http.StatusOK {
		if err := a.validateIssuedCert(body, caPEM, key); err != nil {
			return err
		}
		if err := a.ssl.WriteCert(body); err != nil {
			return err
		}
		fmt.Printf("certificate already issued; stored at %s\n", a.ssl.CertPath())
		return a.report()
	}

	extMap, err := collectExtensions(opts, args)
	if err != nil {
		return err
	}
	exts, err := ppext.BuildExtensions(extMap)
	if err != nil {
		return fmt.Errorf("extension requests: %w", err)
	}
	csrPEM, err := pki.CreateCSR(key, a.certname, splitComma(opts["dns-alt-names"]), exts)
	if err != nil {
		return err
	}
	if len(extMap) > 0 {
		fmt.Printf("requesting %d trusted-fact extension(s): %s\n", len(extMap), joinKeys(extMap))
	}
	if err := a.ssl.WriteCSR(csrPEM); err != nil {
		return err
	}
	if _, code, err := httpPUT(verified, a.caURL("/certificate_request/"+a.certname), csrPEM); err != nil {
		return fmt.Errorf("submit CSR: %w", err)
	} else if code != http.StatusOK {
		return fmt.Errorf("submit CSR: server returned %d", code)
	}
	fmt.Printf("submitted CSR for %q to %s\n", a.certname, a.server)

	cert, err := a.pollForCert(verified, wait)
	if err != nil {
		return err
	}
	if err := a.validateIssuedCert(cert, caPEM, key); err != nil {
		return err
	}
	if err := a.ssl.WriteCert(cert); err != nil {
		return err
	}
	fmt.Printf("certificate issued; stored at %s\n", a.ssl.CertPath())
	return a.report()
}

// ensureCA returns the CA PEM, fetching it trust-on-first-use if the ssldir has
// none yet, otherwise reusing the pinned copy.
func (a *agent) ensureCA() ([]byte, error) {
	if b, err := a.ssl.ReadCACert(); err == nil && len(b) > 0 {
		return b, nil
	}
	tofu := &http.Client{
		Timeout:   30 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}, // ponytail: TOFU, exactly what a fresh Puppet agent does for the first CA fetch
	}
	body, code, err := httpGET(tofu, a.caURL("/certificate/ca"))
	if err != nil {
		return nil, err
	}
	if code != http.StatusOK {
		return nil, fmt.Errorf("CA fetch returned %d", code)
	}
	if _, err := pki.DecodeCert(body); err != nil {
		return nil, fmt.Errorf("CA response is not a certificate: %w", err)
	}
	if err := a.ssl.WriteCACert(body); err != nil {
		return nil, err
	}
	fmt.Printf("pinned CA certificate to %s\n", a.ssl.CACertPath())
	return body, nil
}

func (a *agent) pollForCert(client *http.Client, wait time.Duration) ([]byte, error) {
	interval := 10 * time.Second
	if wait > 0 && wait < interval {
		interval = wait
	}
	deadline := time.Now().Add(wait)
	for {
		body, code, err := httpGET(client, a.caURL("/certificate/"+a.certname))
		if err == nil && code == http.StatusOK {
			return body, nil
		}
		if wait <= 0 {
			return nil, errors.New("certificate not yet signed (run again or have the CA sign it)")
		}
		if time.Now().After(deadline) {
			return nil, fmt.Errorf("gave up waiting for certificate after %s", wait)
		}
		fmt.Printf("waiting for certificate to be signed (retry in %s)...\n", interval)
		time.Sleep(interval)
	}
}

// report prints a short summary of the issued cert, including any Puppet
// trusted-fact extensions the CA copied in (proof of extended-attribute support).
func (a *agent) report() error {
	b, err := os.ReadFile(a.ssl.CertPath())
	if err != nil {
		return err
	}
	crt, err := pki.DecodeCert(b)
	if err != nil {
		return err
	}
	fp := pki.Fingerprints(crt.Raw)["SHA256"]
	fmt.Printf("  subject:     CN=%s\n  serial:      %d\n  not_after:   %s\n  SHA256:      %s\n",
		crt.Subject.CommonName, crt.SerialNumber, crt.NotAfter.UTC().Format(time.RFC3339), fp)
	for k, v := range ppext.Describe(crt.Extensions) {
		fmt.Printf("  ext %s = %s\n", k, v)
	}
	return nil
}

// validateIssuedCert checks a freshly fetched cert before we adopt it as this
// node's identity: it must be a valid PEM cert that chains to the pinned CA,
// carry the certname we asked for, and match our private key.
func (a *agent) validateIssuedCert(certPEM, caPEM []byte, key *rsa.PrivateKey) error {
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
	if crt.Subject.CommonName != a.certname {
		return fmt.Errorf("issued cert CN %q does not match requested certname %q", crt.Subject.CommonName, a.certname)
	}
	pub, ok := crt.PublicKey.(*rsa.PublicKey)
	if !ok || pub.N.Cmp(key.N) != 0 || pub.E != key.E {
		return errors.New("issued cert public key does not match local private key")
	}
	return nil
}

// collectExtensions merges extension_requests from a csr_attributes.yaml
// (--csr-attributes) with repeatable --ext name=value flags (flags win).
func collectExtensions(opts map[string]string, args []string) (map[string]string, error) {
	m := map[string]string{}
	if path := opts["csr-attributes"]; path != "" {
		extReq, custom, err := ppext.ParseCSRAttributes(path)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", path, err)
		}
		maps.Copy(m, extReq)
		if len(custom) > 0 {
			fmt.Fprintf(os.Stderr, "note: custom_attributes (e.g. challengePassword) are parsed but not embedded\n")
		}
	}
	maps.Copy(m, parseExt(args))
	return m, nil
}

// parseExt scans for repeatable `--ext name=value` flags (parseCommon collapses
// repeats, so extensions are gathered separately here).
func parseExt(args []string) map[string]string {
	m := map[string]string{}
	for i := 0; i < len(args); i++ {
		var kv string
		switch {
		case args[i] == "--ext" && i+1 < len(args):
			kv = args[i+1]
			i++
		case strings.HasPrefix(args[i], "--ext="):
			kv = strings.TrimPrefix(args[i], "--ext=")
		default:
			continue
		}
		if k, v, ok := strings.Cut(kv, "="); ok {
			m[strings.TrimSpace(k)] = v
		}
	}
	return m
}

func joinKeys(m map[string]string) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, ", ")
}

// --- mtls demo ------------------------------------------------------------

func cmdMTLS(args []string) error {
	opts, _ := parseCommon(args)
	a, err := newAgent(opts)
	if err != nil {
		return err
	}
	url := opts["url"]
	if url == "" {
		return errors.New("--url https://host/path is required")
	}
	client, err := a.mutualClient()
	if err != nil {
		return err
	}
	body, code, err := httpGET(client, url)
	if err != nil {
		return err
	}
	fmt.Printf("HTTP %d from %s using client cert CN=%s\n", code, url, a.certname)
	_, _ = os.Stdout.Write(body)
	if len(body) > 0 && body[len(body)-1] != '\n' {
		fmt.Println()
	}
	return nil
}

// --- ca admin client ------------------------------------------------------

func cmdCA(args []string) error {
	opts, pos := parseCommon(args)
	if len(pos) == 0 {
		return errors.New("ca <list|sign|revoke> [name]")
	}
	a, err := newAgent(opts)
	if err != nil {
		return err
	}
	client, err := a.mutualClient()
	if err != nil {
		return err
	}
	switch pos[0] {
	case "list":
		body, code, err := httpGET(client, a.baseURL()+"/certificate_statuses/all")
		if err != nil {
			return err
		}
		if code != http.StatusOK {
			return fmt.Errorf("server returned %d: %s", code, body)
		}
		var list []capi.CertStatus
		if err := json.Unmarshal(body, &list); err != nil {
			return err
		}
		for _, s := range list {
			fmt.Printf("%-40s %-10s %s\n", s.Name, s.State, s.Fingerprint)
		}
		return nil
	case "sign", "revoke":
		if len(pos) < 2 {
			return fmt.Errorf("ca %s <name>", pos[0])
		}
		state := capi.StateSigned
		if pos[0] == "revoke" {
			state = capi.StateRevoked
		}
		payload, _ := json.Marshal(capi.DesiredState{DesiredState: state})
		_, code, err := httpPUT(client, a.baseURL()+"/certificate_status/"+url.PathEscape(pos[1]), payload)
		if err != nil {
			return err
		}
		if code != http.StatusNoContent && code != http.StatusOK {
			return fmt.Errorf("server returned %d", code)
		}
		verb := map[string]string{"sign": "signed", "revoke": "revoked"}[pos[0]]
		fmt.Printf("%s: %s\n", pos[1], verb)
		return nil
	default:
		return fmt.Errorf("unknown ca subcommand %q", pos[0])
	}
}

// --- TLS clients ----------------------------------------------------------

// verifiedClient trusts the pinned CA and verifies the server hostname. An
// optional client cert enables mTLS.
func (a *agent) verifiedClient(caPEM []byte, clientCert *tls.Certificate) (*http.Client, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, errors.New("could not parse pinned CA certificate")
	}
	cfg := &tls.Config{RootCAs: pool, ServerName: a.host(), MinVersion: tls.VersionTLS12}
	if clientCert != nil {
		cfg.Certificates = []tls.Certificate{*clientCert}
	}
	return &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: cfg}}, nil
}

// mutualClient builds an mTLS client from the agent's stored key+cert+CA.
func (a *agent) mutualClient() (*http.Client, error) {
	caPEM, err := a.ssl.ReadCACert()
	if err != nil {
		return nil, fmt.Errorf("no pinned CA; run bootstrap first: %w", err)
	}
	cert, err := tls.LoadX509KeyPair(a.ssl.CertPath(), a.ssl.PrivateKeyPath())
	if err != nil {
		return nil, fmt.Errorf("no client cert; run bootstrap first: %w", err)
	}
	return a.verifiedClient(caPEM, &cert)
}

// --- tiny HTTP helpers ----------------------------------------------------

func httpGET(c *http.Client, url string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", capi.PEMContentType)
	return do(c, req)
}

func httpPUT(c *http.Client, url string, body []byte) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPut, url, bytes.NewReader(body))
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Content-Type", capi.PEMContentType)
	return do(c, req)
}

func do(c *http.Client, req *http.Request) ([]byte, int, error) {
	resp, err := c.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	return b, resp.StatusCode, err
}

// --- small utils ----------------------------------------------------------

func defaultCertname() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "agent"
	}
	return h
}

func splitComma(s string) []string {
	var out []string
	for p := range strings.SplitSeq(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func atoiOr(s string, def int) int {
	if n, err := strconv.Atoi(s); err == nil && n > 0 {
		return n
	}
	return def
}

func durationOr(s string, def time.Duration) time.Duration {
	if s == "" {
		return def
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return def
	}
	return d
}
