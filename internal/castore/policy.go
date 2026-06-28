package castore

import (
	"bytes"
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"time"

	"github.com/ncode/facts-ca/internal/ppext"
)

const (
	defaultAutosignPolicyTimeout = 5 * time.Second
	maxAutosignPolicyStderr      = 4 << 10
)

var oidSubjectAltName = asn1.ObjectIdentifier{2, 5, 29, 17}

type policyInput struct {
	Version           int               `json:"version"`
	Certname          string            `json:"certname"`
	SubjectAltNames   policySANs        `json:"subject_alt_names"`
	ExtensionRequests map[string]string `json:"extension_requests"`
	Extensions        policyExtensions  `json:"extensions"`
	Request           policyRequest     `json:"request"`
}

type policySANs struct {
	DNS []string `json:"dns,omitempty"`
	IP  []string `json:"ip,omitempty"`
}

type policyExtensions struct {
	SubjectAltName *policySANs `json:"subject_alt_name,omitempty"`
}

type policyRequest struct {
	SourceIP string `json:"source_ip"`
}

func buildPolicyInput(certname string, csr *x509.CertificateRequest, sourceIP string) (policyInput, error) {
	input := policyInput{
		Version:           1,
		Certname:          certname,
		SubjectAltNames:   policySANsFromCSR(csr),
		ExtensionRequests: map[string]string{},
		Request:           policyRequest{SourceIP: sourceIP},
	}
	for _, ext := range csr.Extensions {
		switch {
		case ext.Id.Equal(oidSubjectAltName):
			sans := policySANsFromCSR(csr)
			input.Extensions.SubjectAltName = &sans
		case ppext.IsPuppetOID(ext.Id):
			v, err := decodePuppetPolicyValue(ext)
			if err != nil {
				return policyInput{}, err
			}
			input.ExtensionRequests[ppext.NameFor(ext.Id)] = v
		case ext.Critical:
			return policyInput{}, fmt.Errorf("unknown critical extension %s", ext.Id)
		}
	}
	return input, nil
}

func policySANsFromCSR(csr *x509.CertificateRequest) policySANs {
	out := policySANs{DNS: append([]string(nil), csr.DNSNames...)}
	for _, ip := range csr.IPAddresses {
		out.IP = append(out.IP, ip.String())
	}
	return out
}

func decodePuppetPolicyValue(ext pkix.Extension) (string, error) {
	var raw asn1.RawValue
	rest, err := asn1.Unmarshal(ext.Value, &raw)
	if err != nil || len(rest) != 0 ||
		raw.Class != asn1.ClassUniversal ||
		(raw.Tag != asn1.TagUTF8String && raw.Tag != asn1.TagPrintableString) {
		return "", fmt.Errorf("decode Puppet extension %s", ext.Id)
	}
	return string(raw.Bytes), nil
}

type policyOutcome int

const (
	policyApproved policyOutcome = iota
	policyDenied
	policyError
)

type policyResult struct {
	outcome policyOutcome
	stderr  string
	err     error
}

func runAutosignPolicy(ctx context.Context, executable string, timeout time.Duration, input policyInput) policyResult {
	if timeout <= 0 {
		timeout = defaultAutosignPolicyTimeout
	}
	body, err := json.Marshal(input)
	if err != nil {
		return policyResult{outcome: policyError, err: fmt.Errorf("marshal policy input: %w", err)}
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, executable)
	cmd.Stdin = bytes.NewReader(body)
	cmd.Stdout = io.Discard
	var stderr cappedBuffer
	cmd.Stderr = &stderr

	err = cmd.Run()
	if errors.Is(ctx.Err(), context.DeadlineExceeded) {
		return policyResult{outcome: policyError, stderr: stderr.String(), err: fmt.Errorf("autosign policy timed out after %s", timeout)}
	}
	if err == nil {
		return policyResult{outcome: policyApproved, stderr: stderr.String()}
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) && exitErr.ExitCode() == 1 {
		return policyResult{outcome: policyDenied, stderr: stderr.String()}
	}
	return policyResult{outcome: policyError, stderr: stderr.String(), err: err}
}

type cappedBuffer struct {
	b []byte
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	if remain := maxAutosignPolicyStderr - len(b.b); remain > 0 {
		if len(p) > remain {
			p = p[:remain]
		}
		b.b = append(b.b, p...)
	}
	return n, nil
}

func (b *cappedBuffer) String() string { return string(b.b) }
