package capi

import (
	"strings"
	"testing"
)

func TestValidCertname(t *testing.T) {
	valid := []string{"host", "host.example.com", "a1.b2-c3_d4", strings.Repeat("a", 255)}
	invalid := []string{"", "UPPER", ".lead", "trail.", "a..b", "a/b", "../x", strings.Repeat("a", 256)}

	for _, name := range valid {
		if !ValidCertname(name) {
			t.Fatalf("ValidCertname(%q) = false, want true", name)
		}
	}
	for _, name := range invalid {
		if ValidCertname(name) {
			t.Fatalf("ValidCertname(%q) = true, want false", name)
		}
	}
}
