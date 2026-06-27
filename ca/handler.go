package ca

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/ncode/facts-ca/internal/capi"
	"github.com/ncode/facts-ca/internal/castore"
	"github.com/ncode/facts-ca/pki"
)

const maxCSRBytes = 1 << 20 // 1 MiB is plenty for a PEM CSR

// Status is the certificate_status JSON body (GET /certificate_status/:name and
// each element of /certificate_statuses/:any). It is the public, re-homed form
// of the internal wire type; field names match puppetserver exactly.
type Status struct {
	Name            string            `json:"name"`
	State           string            `json:"state"`
	Fingerprint     string            `json:"fingerprint"`
	Fingerprints    map[string]string `json:"fingerprints"`
	SubjectAltN     []string          `json:"subject_alt_names"`
	DNSAltN         []string          `json:"dns_alt_names"`
	SerialNumber    json.Number       `json:"serial_number,omitempty"`
	NotBefore       string            `json:"not_before,omitempty"`
	NotAfter        string            `json:"not_after,omitempty"`
	AuthzExtensions map[string]string `json:"authorization_extensions"`
}

// DesiredState is the PUT /certificate_status/:name body: desired_state is
// "signed" or "revoked"; the optional fields override signing defaults.
type DesiredState struct {
	DesiredState string   `json:"desired_state"`
	DNSAltNames  []string `json:"dns_alt_names,omitempty"`
	CertTTL      string   `json:"cert_ttl,omitempty"`
}

// statusFromInternal converts the internal wire status into the public one.
// The JSON tags are identical, so ./interop.sh guards against drift.
func statusFromInternal(s capi.CertStatus) Status {
	return Status{
		Name:            s.Name,
		State:           s.State,
		Fingerprint:     s.Fingerprint,
		Fingerprints:    s.Fingerprints,
		SubjectAltN:     s.SubjectAltN,
		DNSAltN:         s.DNSAltN,
		SerialNumber:    s.SerialNumber,
		NotBefore:       s.NotBefore,
		NotAfter:        s.NotAfter,
		AuthzExtensions: s.AuthzExtensions,
	}
}

// Handler returns the Puppet CA v1 routes so a consumer can mount them on its
// own server (e.g. mux.Handle("/puppet-ca/v1/", c.Handler())) alongside other
// routes. Admin routes require a CA-verified client certificate.
func (c *CA) Handler() http.Handler {
	mux := http.NewServeMux()
	b := capi.Base
	mux.HandleFunc("GET "+b+"/certificate/{name}", c.getCert)
	mux.HandleFunc("PUT "+b+"/certificate_request/{name}", c.putCSR)
	mux.HandleFunc("GET "+b+"/certificate_request/{name}", c.getCSR)
	// Deleting a pending CSR is an admin operation (mTLS-gated) so an
	// unauthenticated caller can't drop another node's request during bootstrap.
	mux.HandleFunc("DELETE "+b+"/certificate_request/{name}", c.admin(c.delCSR))
	mux.HandleFunc("GET "+b+"/certificate_revocation_list/{name}", c.getCRL)
	// CA admin API (mTLS-gated):
	mux.HandleFunc("GET "+b+"/certificate_status/{name}", c.admin(c.getStatus))
	mux.HandleFunc("PUT "+b+"/certificate_status/{name}", c.admin(c.putStatus))
	mux.HandleFunc("DELETE "+b+"/certificate_status/{name}", c.admin(c.delStatus))
	mux.HandleFunc("GET "+b+"/certificate_statuses/{any}", c.admin(c.getStatuses))
	return c.logging(mux)
}

// --- agent endpoints ------------------------------------------------------

func (c *CA) getCert(w http.ResponseWriter, r *http.Request) {
	pem, err := c.store.GetCert(r.PathValue("name"))
	if errors.Is(err, castore.ErrNotFound) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writePEM(w, pem)
}

func (c *CA) putCSR(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxCSRBytes))
	if err != nil {
		http.Error(w, "request too large", http.StatusBadRequest)
		return
	}
	signed, err := c.store.SubmitCSR(r.PathValue("name"), body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	c.log.Info("csr submitted", "name", r.PathValue("name"), "autosigned", signed)
	w.WriteHeader(http.StatusOK)
}

func (c *CA) getCSR(w http.ResponseWriter, r *http.Request) {
	pem, err := c.store.GetCSR(r.PathValue("name"))
	if errors.Is(err, castore.ErrNotFound) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writePEM(w, pem)
}

func (c *CA) delCSR(w http.ResponseWriter, r *http.Request) {
	switch err := c.store.DeleteCSR(r.PathValue("name")); {
	case errors.Is(err, castore.ErrNotFound):
		http.Error(w, "not found", http.StatusNotFound)
	case err != nil:
		http.Error(w, err.Error(), http.StatusInternalServerError)
	default:
		w.WriteHeader(http.StatusNoContent)
	}
}

func (c *CA) getCRL(w http.ResponseWriter, r *http.Request) {
	pem, err := c.store.CRL()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writePEM(w, pem)
}

// --- admin endpoints ------------------------------------------------------

// admin wraps a handler so only callers presenting a CA-verified client cert
// reach it (the Puppet CA admin API requires a whitelisted client cert).
func (c *CA) admin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
			http.Error(w, "client certificate required", http.StatusForbidden)
			return
		}
		next(w, r)
	}
}

func (c *CA) getStatus(w http.ResponseWriter, r *http.Request) {
	st, err := c.store.Status(r.PathValue("name"))
	if errors.Is(err, castore.ErrNotFound) {
		http.Error(w, "not found", http.StatusNotFound)
		return
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, statusFromInternal(st))
}

func (c *CA) getStatuses(w http.ResponseWriter, r *http.Request) {
	list, err := c.Statuses()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, list)
}

func (c *CA) putStatus(w http.ResponseWriter, r *http.Request) {
	var req DesiredState
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16))
	if err := dec.Decode(&req); err != nil {
		http.Error(w, "bad JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if err := dec.Decode(&struct{}{}); err != io.EOF {
		http.Error(w, "bad JSON: trailing data", http.StatusBadRequest) // one object only on a mutating route
		return
	}
	name := r.PathValue("name")
	var err error
	switch req.DesiredState {
	case StateSigned:
		opts := pki.SignOpts{DNSAltNames: req.DNSAltNames}
		if req.CertTTL != "" {
			d, e := time.ParseDuration(req.CertTTL)
			if e != nil {
				http.Error(w, "invalid cert_ttl: "+e.Error(), http.StatusBadRequest)
				return
			}
			if d <= 0 {
				http.Error(w, "invalid cert_ttl: must be positive", http.StatusBadRequest)
				return
			}
			opts.TTL = d
		}
		err = c.store.Sign(name, opts)
	case StateRevoked:
		err = c.store.Revoke(name)
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
		c.log.Info("certificate_status updated", "name", name, "state", req.DesiredState)
		w.WriteHeader(http.StatusNoContent)
	}
}

func (c *CA) delStatus(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	_ = c.store.Revoke(name) // best-effort revoke before clean, matching `puppetserver ca clean`
	switch err := c.store.Clean(name); {
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

func (c *CA) logging(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c.log.Debug("request", "method", r.Method, "path", r.URL.Path)
		next.ServeHTTP(w, r)
	})
}
