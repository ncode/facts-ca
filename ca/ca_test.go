package ca

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"testing"

	"github.com/ncode/facts-ca/internal/capi"
	"github.com/ncode/facts-ca/pki"
)

func newTestCA(t *testing.T, o Options) *CA {
	t.Helper()
	o.Dir = t.TempDir()
	if o.CAName == "" {
		o.CAName = "test-ca"
	}
	c, err := Init(o)
	if err != nil {
		t.Fatalf("Init: %v", err)
	}
	return c
}

func csrPEM(t *testing.T, name string, sans []string) []byte {
	t.Helper()
	key, err := pki.GenerateKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	b, err := pki.CreateCSR(key, name, sans, nil)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// submit PUTs a CSR through the handler and returns the response code.
func submit(t *testing.T, c *CA, name string, csr []byte) int {
	t.Helper()
	req := httptest.NewRequest(http.MethodPut, capi.Base+"/certificate_request/"+name, bytes.NewReader(csr))
	rr := httptest.NewRecorder()
	c.Handler().ServeHTTP(rr, req)
	return rr.Code
}

func TestInitRefusesClobber(t *testing.T) {
	dir := t.TempDir()
	if _, err := Init(Options{Dir: dir, CAName: "x"}); err != nil {
		t.Fatalf("first Init: %v", err)
	}
	if _, err := Init(Options{Dir: dir, CAName: "x"}); err == nil {
		t.Fatal("Init over an existing CA should fail")
	}
}

func TestHandlerServesCAAndGatesAdmin(t *testing.T) {
	c := newTestCA(t, Options{})

	// Agent path: GET certificate/ca returns the CA PEM, no client cert needed.
	req := httptest.NewRequest(http.MethodGet, capi.Base+"/certificate/ca", nil)
	rr := httptest.NewRecorder()
	c.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET certificate/ca = %d, want 200", rr.Code)
	}
	if !bytes.Equal(rr.Body.Bytes(), c.CACertPEM()) {
		t.Fatal("certificate/ca body is not the CA PEM")
	}

	// Put a pending CSR so there is something to list.
	if code := submit(t, c, "node1", csrPEM(t, "node1", nil)); code != http.StatusOK {
		t.Fatalf("submit CSR = %d, want 200", code)
	}

	// Admin path without a verified client cert => 403.
	areq := httptest.NewRequest(http.MethodGet, capi.Base+"/certificate_statuses/all", nil)
	arr := httptest.NewRecorder()
	c.Handler().ServeHTTP(arr, areq)
	if arr.Code != http.StatusForbidden {
		t.Fatalf("admin without client cert = %d, want 403", arr.Code)
	}

	// Admin path with a (faked) verified chain => 200 and lists node1.
	areq2 := httptest.NewRequest(http.MethodGet, capi.Base+"/certificate_statuses/all", nil)
	areq2.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{c.Cert()}}}
	arr2 := httptest.NewRecorder()
	c.Handler().ServeHTTP(arr2, areq2)
	if arr2.Code != http.StatusOK {
		t.Fatalf("admin with client cert = %d, want 200", arr2.Code)
	}
	var list []Status
	if err := json.Unmarshal(arr2.Body.Bytes(), &list); err != nil {
		t.Fatalf("decode statuses: %v", err)
	}
	if len(list) != 1 || list[0].Name != "node1" || list[0].State != capi.StateRequested {
		t.Fatalf("statuses = %+v", list)
	}
}

func TestAutosignDropsSANByDefault(t *testing.T) {
	c := newTestCA(t, Options{AutosignAll: true}) // AllowAltSAN defaults false
	if code := submit(t, c, "web1", csrPEM(t, "web1", []string{"evil.example.com"})); code != http.StatusOK {
		t.Fatalf("submit = %d", code)
	}
	pem, err := c.store.GetCert("web1")
	if err != nil {
		t.Fatalf("autosigned cert missing: %v", err)
	}
	crt, err := pki.DecodeCert(pem)
	if err != nil {
		t.Fatal(err)
	}
	if len(crt.DNSNames) != 0 {
		t.Fatalf("SANs should be dropped by default; got %v", crt.DNSNames)
	}
}

func TestSignThenRevoke(t *testing.T) {
	c := newTestCA(t, Options{})
	if code := submit(t, c, "node2", csrPEM(t, "node2", nil)); code != http.StatusOK {
		t.Fatalf("submit = %d", code)
	}
	if err := c.Sign("node2", pki.SignOpts{}); err != nil {
		t.Fatalf("sign: %v", err)
	}
	if st, _ := c.Status("node2"); st.State != StateSigned {
		t.Fatalf("state after sign = %q, want signed", st.State)
	}
	if err := c.Revoke("node2"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	st, err := c.Status("node2")
	if err != nil {
		t.Fatal(err)
	}
	if st.State != StateRevoked {
		t.Fatalf("state after revoke = %q, want revoked", st.State)
	}
	if st.Fingerprint == "" || st.SerialNumber == "" {
		t.Fatalf("revoked status missing cert fields: %+v", st)
	}
}

func TestHandlerStatusLifecycle(t *testing.T) {
	c := newTestCA(t, Options{})
	name := "node3"
	csr := csrPEM(t, name, nil)
	if code := submit(t, c, name, csr); code != http.StatusOK {
		t.Fatalf("submit = %d", code)
	}

	req := httptest.NewRequest(http.MethodGet, capi.Base+"/certificate_request/"+name, nil)
	rr := httptest.NewRecorder()
	c.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET certificate_request = %d, want 200", rr.Code)
	}
	if !bytes.Equal(rr.Body.Bytes(), csr) {
		t.Fatal("GET certificate_request did not return the stored CSR")
	}

	req = httptest.NewRequest(http.MethodGet, capi.Base+"/certificate_revocation_list/ca", nil)
	rr = httptest.NewRecorder()
	c.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK || !bytes.Contains(rr.Body.Bytes(), []byte("X509 CRL")) {
		t.Fatalf("GET CRL code/body = %d/%q", rr.Code, rr.Body.String())
	}

	body := []byte(`{"desired_state":"signed","cert_ttl":"1h","dns_alt_names":["node3.alt"]}`)
	rr = adminHTTP(t, c, http.MethodPut, capi.Base+"/certificate_status/"+name, bytes.NewReader(body))
	if rr.Code != http.StatusNoContent {
		t.Fatalf("PUT certificate_status sign = %d, want 204: %s", rr.Code, rr.Body.String())
	}

	rr = adminHTTP(t, c, http.MethodGet, capi.Base+"/certificate_status/"+name, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET certificate_status = %d, want 200", rr.Code)
	}
	var st Status
	if err := json.Unmarshal(rr.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if st.State != StateSigned || st.SerialNumber == "" || !slices.Contains(st.DNSAltN, "DNS:node3.alt") {
		t.Fatalf("signed status = %+v", st)
	}

	rr = adminHTTP(t, c, http.MethodPut, capi.Base+"/certificate_status/"+name, bytes.NewReader([]byte(`{"desired_state":"revoked"}`)))
	if rr.Code != http.StatusNoContent {
		t.Fatalf("PUT certificate_status revoke = %d, want 204: %s", rr.Code, rr.Body.String())
	}
	rr = adminHTTP(t, c, http.MethodGet, capi.Base+"/certificate_status/"+name, nil)
	if rr.Code != http.StatusOK {
		t.Fatalf("GET revoked certificate_status = %d, want 200", rr.Code)
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &st); err != nil {
		t.Fatal(err)
	}
	if st.State != StateRevoked {
		t.Fatalf("state after HTTP revoke = %q, want revoked", st.State)
	}

	rr = adminHTTP(t, c, http.MethodDelete, capi.Base+"/certificate_status/"+name, nil)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("DELETE certificate_status = %d, want 204: %s", rr.Code, rr.Body.String())
	}
	rr = adminHTTP(t, c, http.MethodGet, capi.Base+"/certificate_status/"+name, nil)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("GET cleaned certificate_status = %d, want 404", rr.Code)
	}
}

func TestOpenServerTLSConfigAndCleanFacade(t *testing.T) {
	if _, err := Init(Options{}); err == nil {
		t.Fatal("Init without Dir succeeded")
	}
	if _, err := Open(Options{}); err == nil {
		t.Fatal("Open without Dir succeeded")
	}
	if _, err := Open(Options{Dir: filepath.Join(t.TempDir(), "missing")}); !IsNotExist(err) {
		t.Fatalf("Open missing error = %v, want IsNotExist", err)
	}

	dir := t.TempDir()
	if _, err := Init(Options{Dir: dir, CAName: "test-ca", Hostnames: []string{"127.0.0.1"}, Logger: slog.Default()}); err != nil {
		t.Fatal(err)
	}
	c, err := Open(Options{Dir: dir, Hostnames: []string{"127.0.0.1"}})
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	crt := c.Cert()
	crt.Subject.CommonName = "mutated"
	if c.Cert().Subject.CommonName == "mutated" {
		t.Fatal("Cert returned mutable CA state")
	}

	cfg, err := c.ServerTLSConfig()
	if err != nil {
		t.Fatalf("ServerTLSConfig: %v", err)
	}
	if cfg.ClientAuth != tls.VerifyClientCertIfGiven || len(cfg.Certificates) != 1 || cfg.ClientCAs == nil {
		t.Fatalf("unexpected server TLS config: %#v", cfg)
	}

	if code := submit(t, c, "node4", csrPEM(t, "node4", nil)); code != http.StatusOK {
		t.Fatalf("submit = %d", code)
	}
	if err := c.Clean("node4"); err != nil {
		t.Fatalf("Clean pending CSR: %v", err)
	}
	if _, err := c.Status("node4"); err == nil {
		t.Fatal("Status after Clean succeeded, want not found")
	}
	if err := c.ListenAndServe("bad-addr"); err == nil {
		t.Fatal("ListenAndServe with invalid addr succeeded")
	}
}

func TestHandlerErrorsAndCSRDelete(t *testing.T) {
	c := newTestCA(t, Options{})
	h := c.Handler()

	tests := []struct {
		name   string
		method string
		path   string
		body   io.Reader
		want   int
		admin  bool
	}{
		{"missing cert", http.MethodGet, capi.Base + "/certificate/missing", nil, http.StatusNotFound, false},
		{"missing csr", http.MethodGet, capi.Base + "/certificate_request/missing", nil, http.StatusNotFound, false},
		{"bad csr", http.MethodPut, capi.Base + "/certificate_request/bad", bytes.NewReader([]byte("not pem")), http.StatusBadRequest, false},
		{"missing status", http.MethodGet, capi.Base + "/certificate_status/missing", nil, http.StatusNotFound, true},
		{"bad json", http.MethodPut, capi.Base + "/certificate_status/missing", bytes.NewReader([]byte("{")), http.StatusBadRequest, true},
		{"trailing json", http.MethodPut, capi.Base + "/certificate_status/missing", bytes.NewReader([]byte(`{"desired_state":"signed"} {}`)), http.StatusBadRequest, true},
		{"bad ttl", http.MethodPut, capi.Base + "/certificate_status/missing", bytes.NewReader([]byte(`{"desired_state":"signed","cert_ttl":"nope"}`)), http.StatusBadRequest, true},
		{"negative ttl", http.MethodPut, capi.Base + "/certificate_status/missing", bytes.NewReader([]byte(`{"desired_state":"signed","cert_ttl":"-1s"}`)), http.StatusBadRequest, true},
		{"bad desired state", http.MethodPut, capi.Base + "/certificate_status/missing", bytes.NewReader([]byte(`{"desired_state":"bogus"}`)), http.StatusBadRequest, true},
		{"delete missing csr", http.MethodDelete, capi.Base + "/certificate_request/missing", nil, http.StatusNotFound, true},
		{"delete missing status", http.MethodDelete, capi.Base + "/certificate_status/missing", nil, http.StatusNotFound, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, tt.body)
			if tt.admin {
				req.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{c.Cert()}}}
			}
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, req)
			if rr.Code != tt.want {
				t.Fatalf("%s %s = %d, want %d: %s", tt.method, tt.path, rr.Code, tt.want, rr.Body.String())
			}
		})
	}

	csr := csrPEM(t, "pending-delete", nil)
	if code := submit(t, c, "pending-delete", csr); code != http.StatusOK {
		t.Fatalf("submit pending-delete = %d", code)
	}
	rr := adminHTTP(t, c, http.MethodDelete, capi.Base+"/certificate_request/pending-delete", nil)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("DELETE pending CSR = %d, want 204: %s", rr.Code, rr.Body.String())
	}
	rr = httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, capi.Base+"/certificate_request/pending-delete", nil)
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusNotFound {
		t.Fatalf("GET deleted CSR = %d, want 404", rr.Code)
	}
}

func adminHTTP(t *testing.T, c *CA, method, target string, body io.Reader) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, target, body)
	req.TLS = &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{c.Cert()}}}
	rr := httptest.NewRecorder()
	c.Handler().ServeHTTP(rr, req)
	return rr
}
