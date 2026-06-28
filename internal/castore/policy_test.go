package castore

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ncode/facts-ca/internal/capi"
	"github.com/ncode/facts-ca/internal/ppext"
	"github.com/ncode/facts-ca/pki"
)

func TestMain(m *testing.M) {
	if mode := os.Getenv("FACTS_CA_POLICY_TEST_HELPER"); mode != "" {
		runPolicyTestHelper(mode)
		return
	}
	os.Exit(m.Run())
}

func TestPolicyInputJSON(t *testing.T) {
	exts, err := ppext.BuildExtensions(map[string]string{
		"pp_role":                  "web",
		"1.3.6.1.4.1.34380.1.2.99": "custom",
		"1.3.6.1.4.1.34380.1.3.13": "admin",
	})
	if err != nil {
		t.Fatal(err)
	}
	exts = append(exts, pkix.Extension{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Value: []byte{0x05, 0x00}})
	csr := parsedCSR(t, "node.example", []string{"alt.example", "127.0.0.1"}, exts)

	input, err := buildPolicyInput("node.example", csr, "203.0.113.9")
	if err != nil {
		t.Fatal(err)
	}
	b, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}

	want := `{"version":1,"certname":"node.example","subject_alt_names":{"dns":["node.example","alt.example"],"ip":["127.0.0.1"]},"extension_requests":{"1.3.6.1.4.1.34380.1.2.99":"custom","pp_auth_role":"admin","pp_role":"web"},"extensions":{"subject_alt_name":{"dns":["node.example","alt.example"],"ip":["127.0.0.1"]}},"request":{"source_ip":"203.0.113.9"}}`
	if string(b) != want {
		t.Fatalf("policy JSON = %s\nwant        = %s", b, want)
	}
	if strings.Contains(string(b), "1.2.3.4") {
		t.Fatal("unknown non-critical extension leaked into policy JSON")
	}
}

func TestPolicyInputRejectsUnknownCriticalExtension(t *testing.T) {
	csr := parsedCSR(t, "node", nil, []pkix.Extension{
		{Id: asn1.ObjectIdentifier{1, 2, 3, 4}, Critical: true, Value: []byte{0x05, 0x00}},
	})
	if _, err := buildPolicyInput("node", csr, ""); err == nil || !strings.Contains(err.Error(), "unknown critical extension") {
		t.Fatalf("buildPolicyInput error = %v, want unknown critical extension", err)
	}
}

func TestRunAutosignPolicy(t *testing.T) {
	input := policyInput{Version: 1, Certname: "node"}
	longTimeout := 5 * time.Second
	tests := []struct {
		name    string
		mode    string
		timeout time.Duration
		want    policyOutcome
		wantErr bool
	}{
		{"approve", "inspect", longTimeout, policyApproved, false},
		{"deny", "deny", longTimeout, policyDenied, false},
		{"timeout", "sleep", 10 * time.Millisecond, policyError, true},
		{"execution error", "", longTimeout, policyError, true},
		{"exit 2", "exit2", longTimeout, policyError, true},
		{"stdout ignored", "stdout-approve-deny", longTimeout, policyDenied, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exe := filepath.Join(t.TempDir(), "missing")
			if tt.mode != "" {
				exe = policyExecutable(t, tt.mode)
			}
			if tt.mode == "inspect" {
				wd, err := os.Getwd()
				if err != nil {
					t.Fatal(err)
				}
				t.Setenv("FACTS_CA_POLICY_EXPECT_ENV", "present")
				t.Setenv("FACTS_CA_POLICY_EXPECT_CWD", wd)
			}
			got := runAutosignPolicy(context.Background(), exe, tt.timeout, input)
			if got.outcome != tt.want {
				t.Fatalf("outcome = %v, want %v (err=%v stderr=%q)", got.outcome, tt.want, got.err, got.stderr)
			}
			if (got.err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", got.err, tt.wantErr)
			}
		})
	}
}

func TestRunAutosignPolicyCapsStderr(t *testing.T) {
	got := runAutosignPolicy(context.Background(), policyExecutable(t, "stderr"), 5*time.Second, policyInput{Version: 1, Certname: "node"})
	if got.outcome != policyError || got.err == nil {
		t.Fatalf("result = %+v, want policy error", got)
	}
	if len(got.stderr) != maxAutosignPolicyStderr {
		t.Fatalf("stderr len = %d, want %d", len(got.stderr), maxAutosignPolicyStderr)
	}
}

func TestPolicyConfigValidation(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		opts Options
	}{
		{"executable without autosign", Options{AutosignPolicyExecutable: exe}},
		{"timeout without executable", Options{AutosignPolicyTimeout: time.Second}},
		{"relative executable", Options{AutosignAll: true, AutosignPolicyExecutable: "relative-policy"}},
		{"missing executable", Options{AutosignAll: true, AutosignPolicyExecutable: filepath.Join(t.TempDir(), "missing")}},
		{"directory executable", Options{AutosignAll: true, AutosignPolicyExecutable: t.TempDir()}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := Init(t.TempDir(), "test-ca", 2048, tt.opts); err == nil {
				t.Fatal("Init succeeded, want validation error")
			}
		})
	}

	ca, err := Init(t.TempDir(), "test-ca", 2048, Options{AutosignAll: true, AutosignPolicyExecutable: exe})
	if err != nil {
		t.Fatalf("Init valid policy: %v", err)
	}
	if ca.policyTimeout != defaultAutosignPolicyTimeout {
		t.Fatalf("policy timeout = %s, want %s", ca.policyTimeout, defaultAutosignPolicyTimeout)
	}
}

func TestSubmitCSRPolicyIntegration(t *testing.T) {
	tests := []struct {
		name      string
		mode      string
		wantSign  bool
		wantState string
	}{
		{"approve signs", "approve", true, capi.StateSigned},
		{"deny stays pending", "deny", false, capi.StateRequested},
		{"policy error stays pending", "exit2", false, capi.StateRequested},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ca := mustInit(t, Options{
				AutosignAll:              true,
				AutosignPolicyExecutable: policyExecutable(t, tt.mode),
				AutosignPolicyTimeout:    5 * time.Second,
			})
			signed, err := ca.SubmitCSR(tt.mode, csrFor(t, tt.mode))
			if err != nil {
				t.Fatal(err)
			}
			if signed != tt.wantSign {
				t.Fatalf("signed = %v, want %v", signed, tt.wantSign)
			}
			st, err := ca.Status(tt.mode)
			if err != nil {
				t.Fatal(err)
			}
			if st.State != tt.wantState {
				t.Fatalf("state = %q, want %q", st.State, tt.wantState)
			}
		})
	}
}

func TestSubmitCSRPolicyNormalizationErrorDoesNotStore(t *testing.T) {
	roleOID, err := ppext.ResolveOID("pp_role")
	if err != nil {
		t.Fatal(err)
	}
	csr := csrPEMWithExtensions(t, "bad-policy", []pkix.Extension{{Id: roleOID, Value: []byte{0xff}}})
	ca := mustInit(t, Options{
		AutosignAll:              true,
		AutosignPolicyExecutable: policyExecutable(t, "approve"),
		AutosignPolicyTimeout:    5 * time.Second,
	})
	if _, err := ca.SubmitCSR("bad-policy", csr); err == nil {
		t.Fatal("SubmitCSR succeeded, want normalization error")
	}
	if _, err := ca.GetCSR("bad-policy"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetCSR after rejected policy input = %v, want ErrNotFound", err)
	}
}

func TestSubmitCSRPolicyResubmissionRerunsPolicy(t *testing.T) {
	t.Setenv("FACTS_CA_POLICY_COUNT_FILE", filepath.Join(t.TempDir(), "count"))
	ca := mustInit(t, Options{
		AutosignAll:              true,
		AutosignPolicyExecutable: policyExecutable(t, "deny-then-approve"),
		AutosignPolicyTimeout:    5 * time.Second,
	})
	csr := csrFor(t, "rerun")
	signed, err := ca.SubmitCSR("rerun", csr)
	if err != nil {
		t.Fatal(err)
	}
	if signed {
		t.Fatal("first submit signed, want pending")
	}
	signed, err = ca.SubmitCSR("rerun", csr)
	if err != nil {
		t.Fatal(err)
	}
	if !signed {
		t.Fatal("second submit did not sign after policy approval")
	}
}

func TestSubmitCSRPolicySignsOnlySamePendingCSR(t *testing.T) {
	ca := mustInit(t, Options{
		AutosignAll:              true,
		AutosignPolicyExecutable: policyExecutable(t, "approve-mutate-request"),
		AutosignPolicyTimeout:    5 * time.Second,
	})
	t.Setenv("FACTS_CA_POLICY_MUTATE_PATH", filepath.Join(ca.dir, "requests", "race.pem"))
	signed, err := ca.SubmitCSR("race", csrFor(t, "race"))
	if err != nil {
		t.Fatal(err)
	}
	if signed {
		t.Fatal("SubmitCSR signed after policy mutated the pending request")
	}
	if _, err := ca.GetCert("race"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("GetCert after mutated request = %v, want ErrNotFound", err)
	}
}

func parsedCSR(t *testing.T, name string, sans []string, exts []pkix.Extension) *x509.CertificateRequest {
	t.Helper()
	csr, err := pki.DecodeCSR(csrPEMWithSANsAndExtensions(t, name, sans, exts))
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

func csrPEMWithExtensions(t *testing.T, name string, exts []pkix.Extension) []byte {
	t.Helper()
	return csrPEMWithSANsAndExtensions(t, name, nil, exts)
}

func csrPEMWithSANsAndExtensions(t *testing.T, name string, sans []string, exts []pkix.Extension) []byte {
	t.Helper()
	key, err := pki.GenerateKey(2048)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := pki.CreateCSR(key, name, sans, exts)
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

func policyExecutable(t *testing.T, mode string) string {
	t.Helper()
	t.Setenv("FACTS_CA_POLICY_TEST_HELPER", mode)
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	return exe
}

func runPolicyTestHelper(mode string) {
	in, _ := io.ReadAll(os.Stdin)
	switch mode {
	case "inspect":
		wd, _ := os.Getwd()
		if len(os.Args) != 1 ||
			!strings.Contains(string(in), `"certname":"node"`) ||
			os.Getenv("FACTS_CA_POLICY_EXPECT_ENV") != "present" ||
			wd != os.Getenv("FACTS_CA_POLICY_EXPECT_CWD") {
			os.Exit(2)
		}
		os.Stdout.WriteString("ignored\n")
		os.Exit(0)
	case "approve":
		os.Exit(0)
	case "deny":
		os.Exit(1)
	case "stdout-approve-deny":
		os.Stdout.WriteString(`{"approve":true}`)
		os.Exit(1)
	case "exit2":
		os.Stderr.WriteString("policy broke")
		os.Exit(2)
	case "stderr":
		os.Stderr.WriteString(strings.Repeat("x", maxAutosignPolicyStderr+100))
		os.Exit(2)
	case "sleep":
		time.Sleep(time.Minute)
		os.Exit(0)
	case "deny-then-approve":
		path := os.Getenv("FACTS_CA_POLICY_COUNT_FILE")
		if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
			_ = os.WriteFile(path, []byte("1"), 0o644)
			os.Exit(1)
		}
		os.Exit(0)
	case "approve-mutate-request":
		_ = os.WriteFile(os.Getenv("FACTS_CA_POLICY_MUTATE_PATH"), []byte("not the approved csr"), 0o644)
		os.Exit(0)
	default:
		os.Exit(2)
	}
}
