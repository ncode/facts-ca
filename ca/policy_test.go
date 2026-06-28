package ca

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ncode/facts-ca/internal/capi"
)

func TestMain(m *testing.M) {
	if os.Getenv("FACTS_CA_HANDLER_POLICY_HELPER") != "" {
		b, _ := io.ReadAll(os.Stdin)
		_ = os.WriteFile(os.Getenv("FACTS_CA_HANDLER_POLICY_CAPTURE"), b, 0o644)
		os.Exit(1)
	}
	os.Exit(m.Run())
}

func TestHandlerPassesDirectPeerIPToPolicy(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	capture := filepath.Join(t.TempDir(), "policy.json")
	t.Setenv("FACTS_CA_HANDLER_POLICY_HELPER", "1")
	t.Setenv("FACTS_CA_HANDLER_POLICY_CAPTURE", capture)

	c := newTestCA(t, Options{
		AutosignAll:              true,
		AutosignPolicyExecutable: exe,
		AutosignPolicyTimeout:    5 * time.Second,
	})
	req := httptest.NewRequest(http.MethodPut, capi.Base+"/certificate_request/source-ip", bytes.NewReader(csrPEM(t, "source-ip", nil)))
	req.RemoteAddr = "198.51.100.9:4321"
	req.Header.Set("X-Forwarded-For", "203.0.113.77")
	rr := httptest.NewRecorder()
	c.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("submit = %d: %s", rr.Code, rr.Body.String())
	}

	b, err := os.ReadFile(capture)
	if err != nil {
		t.Fatal(err)
	}
	var got struct {
		Request struct {
			SourceIP string `json:"source_ip"`
		} `json:"request"`
	}
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if got.Request.SourceIP != "198.51.100.9" {
		t.Fatalf("source_ip = %q, want direct peer IP", got.Request.SourceIP)
	}
}
