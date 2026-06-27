// facts-ca-cli is a thin adapter over the agent package: it bootstraps a
// Puppet-compatible certificate (trust-on-first-use, like a fresh Puppet agent),
// stores it in a Puppet ssldir, and can then open mTLS connections or drive the
// CA admin API with the result.
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
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
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

	"github.com/ncode/facts-ca/agent"
	"github.com/ncode/facts-ca/ca"
	"github.com/ncode/facts-ca/internal/capi"
	"github.com/ncode/facts-ca/internal/ppext"
	"github.com/ncode/facts-ca/internal/ssldir"
	"github.com/ncode/facts-ca/internal/version"
	"github.com/ncode/facts-ca/pki"
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

// common holds the resolved server/certname/ssldir shared by every subcommand.
type common struct {
	server   string // host:port
	host     string // host only, for the TLS ServerName
	certname string
	dir      string
}

func resolveCommon(opts map[string]string) (*common, error) {
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
	host, _, _ := net.SplitHostPort(server)
	return &common{server: server, host: host, certname: certname, dir: dir}, nil
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

// --- bootstrap ------------------------------------------------------------

func cmdBootstrap(args []string) error {
	opts, _ := parseCommon(args)
	c, err := resolveCommon(opts)
	if err != nil {
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
	// If a complete identity already loads, this is a reuse, not a fresh
	// issuance: skip extension parsing (no CSR will be generated) and report it
	// as such. (A partial ssldir fails to load and still enrolls with extensions.)
	_, loadErr := agent.Load(c.dir, c.certname)
	alreadyHad := loadErr == nil
	var extMap map[string]string
	if !alreadyHad {
		extMap, err = collectExtensions(opts, args)
		if err != nil {
			return err
		}
		if len(extMap) > 0 {
			fmt.Printf("requesting %d trusted-fact extension(s): %s\n", len(extMap), joinKeys(extMap))
		}
	}

	id, err := agent.Enroll(context.Background(), agent.Config{
		Server:          c.server,
		Certname:        c.certname,
		Dir:             c.dir,
		KeyBits:         keylen,
		DNSAltNames:     splitComma(opts["dns-alt-names"]),
		Extensions:      extMap,
		TrustOnFirstUse: true, // a fresh Puppet agent trusts the CA on first fetch
		WaitForCert:     wait,
		Logger:          slog.Default(),
	})
	if err != nil {
		return err
	}
	state := "issued"
	if alreadyHad {
		state = "already issued"
	}
	fmt.Printf("certificate %s; stored at %s\n", state, ssldir.New(c.dir, id.Certname()).CertPath())
	report(id)
	return nil
}

// report prints a short summary of the issued cert, including any Puppet
// trusted-fact extensions the CA copied in (proof of extended-attribute support).
func report(id *agent.Identity) {
	crt := id.Certificate().Leaf
	fp := pki.Fingerprints(crt.Raw)["SHA256"]
	fmt.Printf("  subject:     CN=%s\n  serial:      %d\n  not_after:   %s\n  SHA256:      %s\n",
		crt.Subject.CommonName, crt.SerialNumber, crt.NotAfter.UTC().Format(time.RFC3339), fp)
	for k, v := range ppext.Describe(crt.Extensions) {
		fmt.Printf("  ext %s = %s\n", k, v)
	}
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
	c, err := resolveCommon(opts)
	if err != nil {
		return err
	}
	target := opts["url"]
	if target == "" {
		return errors.New("--url https://host/path is required")
	}
	id, err := loadIdentity(c)
	if err != nil {
		return err
	}
	// Verify the dialed service against the pinned CA (HTTPClient uses the URL's
	// host as ServerName), so mtls works for any service, not only the CA host.
	body, code, err := httpGET(id.HTTPClient(), target)
	if err != nil {
		return err
	}
	fmt.Printf("HTTP %d from %s using client cert CN=%s\n", code, target, id.Certname())
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
	c, err := resolveCommon(opts)
	if err != nil {
		return err
	}
	id, err := loadIdentity(c)
	if err != nil {
		return err
	}
	client := mtlsClient(id, c.host)
	base := "https://" + c.server + capi.Base
	switch pos[0] {
	case "list":
		body, code, err := httpGET(client, base+"/certificate_statuses/all")
		if err != nil {
			return err
		}
		if code != http.StatusOK {
			return fmt.Errorf("server returned %d: %s", code, body)
		}
		var list []ca.Status
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
		state := ca.StateSigned
		if pos[0] == "revoke" {
			state = ca.StateRevoked
		}
		payload, _ := json.Marshal(ca.DesiredState{DesiredState: state})
		_, code, err := httpPUT(client, base+"/certificate_status/"+url.PathEscape(pos[1]), payload)
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

// loadIdentity loads the already-bootstrapped identity from the ssldir with no
// network and no disk mutation; it errors if the dir has not been bootstrapped.
func loadIdentity(c *common) (*agent.Identity, error) {
	return agent.Load(c.dir, c.certname)
}

func mtlsClient(id *agent.Identity, host string) *http.Client {
	return &http.Client{Timeout: 30 * time.Second, Transport: &http.Transport{TLSClientConfig: id.ClientTLSConfig(host)}}
}

// --- tiny HTTP helpers ----------------------------------------------------

func httpGET(c *http.Client, target string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Accept", capi.PEMContentType)
	return do(c, req)
}

func httpPUT(c *http.Client, target string, body []byte) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPut, target, bytes.NewReader(body))
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

// parseCommon parses --key value / --key=value / boolean flags by hand to stay
// dependency-free, returning the flag map and any positional args.
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
