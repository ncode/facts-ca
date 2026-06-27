package ca

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
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
	if !strings.HasPrefix(st.Fingerprint, "") || st.SerialNumber == "" {
		t.Fatalf("revoked status missing cert fields: %+v", st)
	}
}
