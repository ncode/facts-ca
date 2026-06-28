package capi

import (
	"strings"
	"testing"
)

func BenchmarkValidCertname(b *testing.B) {
	cases := []string{
		"node.example.com",
		"a1.b2-c3_d4",
		strings.Repeat("a", 255),
		"../bad",
		"UPPER",
		strings.Repeat("a", 256),
	}
	b.ReportAllocs()
	for b.Loop() {
		for _, name := range cases {
			_ = ValidCertname(name)
		}
	}
}
