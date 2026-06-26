// facts-ca-server is a Go port of the Puppet CA service. It speaks the Puppet
// CA v1 HTTP API over mTLS so real Puppet agents (and facts-ca-cli) can
// bootstrap certificates against it.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/ncode/facts-ca/internal/capi"
	"github.com/ncode/facts-ca/internal/castore"
	"github.com/ncode/facts-ca/internal/pki"
	"github.com/ncode/facts-ca/internal/version"
)

const maxCSRBytes = 1 << 20 // 1 MiB is plenty for a PEM CSR

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version", "--version", "-v":
			fmt.Println(version.Version)
			return
		case "sign", "revoke", "list", "clean":
			adminMain(os.Args[1], os.Args[2:])
			return
		}
	}
	serveMain()
}

// adminMain implements the offline CA operations (`facts-ca-server sign NODE`,
// the equivalent of `puppetserver ca sign`), acting directly on the cadir.
func adminMain(action string, args []string) {
	fs := flag.NewFlagSet(action, flag.ExitOnError)
	cadir := fs.String("cadir", "./cadir", "CA state directory")
	ttl := fs.Duration("ttl", pki.DefaultCATTL, "lifetime of issued certificates (sign only)")
	_ = fs.Parse(args)

	ca, err := castore.Open(*cadir, castore.Options{TTL: *ttl})
	if err != nil {
		fatal("open CA: %v", err)
	}
	switch action {
	case "list":
		list, err := ca.Statuses()
		if err != nil {
			fatal("list: %v", err)
		}
		for _, s := range list {
			fmt.Printf("%-40s %-10s %s\n", s.Name, s.State, s.Fingerprint)
		}
	case "sign", "revoke", "clean":
		name := fs.Arg(0)
		if name == "" {
			fatal("usage: facts-ca-server %s <certname>", action)
		}
		switch action {
		case "sign":
			err = ca.Sign(name, pki.SignOpts{})
		case "revoke":
			err = ca.Revoke(name)
		case "clean":
			_ = ca.Revoke(name)
			err = ca.Clean(name)
		}
		if err != nil {
			fatal("%s %s: %v", action, name, err)
		}
		fmt.Printf("%s: %s\n", name, action+"d")
	}
}

func serveMain() {
	var (
		cadir    = flag.String("cadir", "./cadir", "CA state directory (puppetserver cadir layout)")
		listen   = flag.String("listen", ":8140", "HTTPS listen address (Puppet uses 8140)")
		hostname = flag.String("hostname", defaultHostname(), "server FQDN(s), comma-separated, for its TLS cert")
		caName   = flag.String("ca-name", "", "CA subject name (default: first hostname)")
		doInit   = flag.Bool("init", false, "initialize the CA in -cadir if absent")
		autosign = flag.Bool("autosign", false, "auto-sign every incoming CSR (insecure)")
		ttl      = flag.Duration("ttl", pki.DefaultCATTL, "lifetime of issued certificates")
		altSAN   = flag.Bool("allow-dns-alt-names", false, "honor subjectAltNames in agent CSRs (puppetserver default: off)")
	)
	flag.Parse()

	hostnames := splitComma(*hostname)
	if len(hostnames) == 0 {
		fatal("-hostname must contain at least one non-empty hostname")
	}
	opts := castore.Options{TTL: *ttl, AutosignAll: *autosign, AllowAltSAN: *altSAN}

	ca, err := castore.Open(*cadir, opts)
	if errors.Is(err, os.ErrNotExist) || (err != nil && strings.Contains(err.Error(), "no such file")) {
		if !*doInit {
			fatal("no CA at %s (pass -init to create one): %v", *cadir, err)
		}
		name := *caName
		if name == "" {
			name = hostnames[0]
		}
		ca, err = castore.Init(*cadir, name, 0, opts)
		if err != nil {
			fatal("init CA: %v", err)
		}
		slog.Info("initialized CA", "dir", *cadir, "name", name)
	} else if err != nil {
		fatal("open CA: %v", err)
	}

	srvCert, err := ca.ServerTLSCert(hostnames)
	if err != nil {
		fatal("server cert: %v", err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert())

	srv := &http.Server{
		Addr:    *listen,
		Handler: routes(&handler{ca: ca}),
		TLSConfig: &tls.Config{
			Certificates: []tls.Certificate{srvCert},
			ClientCAs:    pool,
			// Agents bootstrap without a cert (CSR submit, cert fetch); admin
			// endpoints separately require a verified client cert.
			ClientAuth: tls.VerifyClientCertIfGiven,
			MinVersion: tls.VersionTLS12,
		},
		ReadHeaderTimeout: 10 * time.Second,
	}
	slog.Info("facts-ca-server listening", "addr", *listen, "autosign", *autosign)
	if err := srv.ListenAndServeTLS("", ""); err != nil {
		fatal("serve: %v", err)
	}
}

type handler struct{ ca *castore.CA }

func routes(h *handler) http.Handler {
	mux := http.NewServeMux()
	b := capi.Base
	mux.HandleFunc("GET "+b+"/certificate/{name}", h.getCert)
	mux.HandleFunc("PUT "+b+"/certificate_request/{name}", h.putCSR)
	mux.HandleFunc("GET "+b+"/certificate_request/{name}", h.getCSR)
	// Deleting a pending CSR is an admin operation (mTLS-gated) so an
	// unauthenticated caller can't drop another node's request during bootstrap.
	mux.HandleFunc("DELETE "+b+"/certificate_request/{name}", h.admin(h.delCSR))
	mux.HandleFunc("GET "+b+"/certificate_revocation_list/{name}", h.getCRL)
	// CA admin API (mTLS-gated):
	mux.HandleFunc("GET "+b+"/certificate_status/{name}", h.admin(h.getStatus))
	mux.HandleFunc("PUT "+b+"/certificate_status/{name}", h.admin(h.putStatus))
	mux.HandleFunc("DELETE "+b+"/certificate_status/{name}", h.admin(h.delStatus))
	mux.HandleFunc("GET "+b+"/certificate_statuses/{any}", h.admin(h.getStatuses))
	return logging(mux)
}

// --- agent endpoints ------------------------------------------------------

func (h *handler) getCert(w http.ResponseWriter, r *http.Request) {
	pem, err := h.ca.GetCert(r.PathValue("name"))
	if errors.Is(err, castore.ErrNotFound) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writePEM(w, pem)
}

func (h *handler) putCSR(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxCSRBytes))
	if err != nil {
		http.Error(w, "request too large", http.StatusBadRequest)
		return
	}
	signed, err := h.ca.SubmitCSR(r.PathValue("name"), body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	slog.Info("csr submitted", "name", r.PathValue("name"), "autosigned", signed)
	w.WriteHeader(http.StatusOK)
}

func (h *handler) getCSR(w http.ResponseWriter, r *http.Request) {
	pem, err := h.ca.GetCSR(r.PathValue("name"))
	if errors.Is(err, castore.ErrNotFound) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writePEM(w, pem)
}

func (h *handler) delCSR(w http.ResponseWriter, r *http.Request) {
	switch err := h.ca.DeleteCSR(r.PathValue("name")); {
	case errors.Is(err, castore.ErrNotFound):
		http.Error(w, "not found", http.StatusNotFound)
	case err != nil:
		http.Error(w, err.Error(), http.StatusInternalServerError)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

func (h *handler) getCRL(w http.ResponseWriter, r *http.Request) {
	pem, err := h.ca.CRL()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writePEM(w, pem)
}

// --- admin endpoints ------------------------------------------------------

// admin wraps a handler so only callers presenting a CA-verified client cert
// reach it (the Puppet CA admin API requires a whitelisted client cert).
func (h *handler) admin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
			http.Error(w, "client certificate required", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

func (h *handler) getStatus(w http.ResponseWriter, r *http.Request) {
	st, err := h.ca.Status(r.PathValue("name"))
	if errors.Is(err, castore.ErrNotFound) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, st)
}

func (h *handler) getStatuses(w http.ResponseWriter, r *http.Request) {
	list, err := h.ca.Statuses()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, list)
}

func (h *handler) putStatus(w http.ResponseWriter, r *http.Request) {
	var req capi.DesiredState
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<16)).Decode(&req); err != nil {
		http.Error(w, "bad JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	name := r.PathValue("name")
	var err error
	switch req.DesiredState {
	case capi.StateSigned:
		opts := pki.SignOpts{DNSAltNames: req.DNSAltNames}
		if req.CertTTL != "" {
			d, e := time.ParseDuration(req.CertTTL)
			if e != nil {
				http.Error(w, "invalid cert_ttl: "+e.Error(), http.StatusBadRequest)
				return
			}
			opts.TTL = d
		}
		err = h.ca.Sign(name, opts)
	case capi.StateRevoked:
		err = h.ca.Revoke(name)
	default:
		http.Error(w, "desired_state must be signed or revoked", http.StatusBadRequest)
		return
	}
	switch {
	case errors.Is(err, castore.ErrNotFound):
		http.Error(w, "not found", http.StatusNotFound)
	case err != nil:
		http.Error(w, err.Error(), http.StatusConflict)
	default:
		slog.Info("certificate_status updated", "name", name, "state", req.DesiredState)
		w.WriteHeader(http.StatusNoContent)
	}
}

func (h *handler) delStatus(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	_ = h.ca.Revoke(name) // best-effort revoke before clean, matching `puppetserver ca clean`
	switch err := h.ca.Clean(name); {
	case errors.Is(err, castore.ErrNotFound):
		http.Error(w, "not found", http.StatusNotFound)
	case err != nil:
		http.Error(w, err.Error(), http.StatusInternalServerError)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

// --- helpers --------------------------------------------------------------

func writePEM(w http.ResponseWriter, pem []byte) {
	w.Header().Set("Content-Type", capi.PEMContentType)
	_, _ = w.Write(pem)
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		slog.Debug("request", "method", r.Method, "path", r.URL.Path)
		next.ServeHTTP(w, r)
	})
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

func defaultHostname() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "localhost"
	}
	return h
}

func fatal(format string, args ...any) {
	slog.Error(fmt.Sprintf(format, args...))
	os.Exit(1)
}
