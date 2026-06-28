package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"testing"

	capkg "github.com/ncode/facts-ca/ca"
	"github.com/ncode/facts-ca/internal/capi"
	"github.com/ncode/facts-ca/pki"
)

func TestMainVersion(t *testing.T) {
	old := os.Args
	t.Cleanup(func() { os.Args = old })
	os.Args = []string{"facts-ca-server", "version"}
	main()
}

func TestAdminMainOfflineFlow(t *testing.T) {
	dir := t.TempDir()
	c, err := capkg.Init(capkg.Options{Dir: dir, CAName: "test-ca"})
	if err != nil {
		t.Fatal(err)
	}
	submitCSR(t, c, "node1")

	old := os.Args
	t.Cleanup(func() { os.Args = old })
	os.Args = []string{"facts-ca-server", "sign", "-cadir", dir, "node1"}
	main()

	reopened, err := capkg.Open(capkg.Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	if st, err := reopened.Status("node1"); err != nil || st.State != capkg.StateSigned {
		t.Fatalf("status after sign = %+v, %v", st, err)
	}

	adminMain("list", []string{"-cadir", dir})
	adminMain("revoke", []string{"-cadir", dir, "node1"})
	if st, err := reopened.Status("node1"); err != nil || st.State != capkg.StateRevoked {
		t.Fatalf("status after revoke = %+v, %v", st, err)
	}
	adminMain("clean", []string{"-cadir", dir, "node1"})
	if _, err := reopened.Status("node1"); err == nil {
		t.Fatal("status after clean succeeded, want not found")
	}
}

func TestServerSmallUtils(t *testing.T) {
	if got := splitComma(" a, ,b,, c "); !slices.Equal(got, []string{"a", "b", "c"}) {
		t.Fatalf("splitComma = %v", got)
	}
	if defaultHostname() == "" {
		t.Fatal("defaultHostname returned empty string")
	}
}

func submitCSR(t *testing.T, c *capkg.CA, name string) {
	t.Helper()
	key, err := pki.GenerateKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := pki.CreateCSR(key, name, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPut, capi.Base+"/certificate_request/"+name, bytes.NewReader(csr))
	rr := httptest.NewRecorder()
	c.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("submit CSR = %d: %s", rr.Code, rr.Body.String())
	}
}
