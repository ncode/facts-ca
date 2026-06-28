package ppext

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func BenchmarkResolveOID(b *testing.B) {
	for _, name := range []string{"pp_role", "pp_authorization", "1.3.6.1.4.1.34380.1.2.99"} {
		b.Run(name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				oid, err := ResolveOID(name)
				if err != nil {
					b.Fatal(err)
				}
				if len(oid) == 0 {
					b.Fatal("empty OID")
				}
			}
		})
	}
}

func BenchmarkBuildExtensions(b *testing.B) {
	input := map[string]string{
		"pp_uuid":                  "ED803750-E3C7-44F5-BB08-41A04433FE2E",
		"pp_role":                  "web",
		"pp_environment":           "production",
		"pp_authorization":         "true",
		"pp_auth_role":             "admin",
		"1.3.6.1.4.1.34380.1.2.99": "custom",
	}
	b.ReportAllocs()
	for b.Loop() {
		exts, err := BuildExtensions(input)
		if err != nil {
			b.Fatal(err)
		}
		if len(exts) != len(input) {
			b.Fatalf("extensions = %d, want %d", len(exts), len(input))
		}
	}
}

func BenchmarkExtensionFilters(b *testing.B) {
	exts, err := BuildExtensions(map[string]string{
		"pp_role":                  "web",
		"pp_authorization":         "true",
		"1.2.3.4":                  "dropped",
		"1.3.6.1.4.1.34380.1.2.99": "custom",
	})
	if err != nil {
		b.Fatal(err)
	}
	b.Run("allowed-from-csr", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if len(AllowedFromCSR(exts)) == 0 {
				b.Fatal("no allowed extensions")
			}
		}
	})
	b.Run("describe", func(b *testing.B) {
		allowed := AllowedFromCSR(exts)
		b.ReportAllocs()
		for b.Loop() {
			got := Describe(allowed)
			if got["pp_role"] == "" {
				b.Fatal("missing role")
			}
		}
	})
	b.Run("auth-extensions", func(b *testing.B) {
		allowed := AllowedFromCSR(exts)
		b.ReportAllocs()
		for b.Loop() {
			got := AuthExtensions(allowed)
			if got["pp_authorization"] == "" {
				b.Fatal("missing auth extension")
			}
		}
	})
}

func BenchmarkParseCSRAttributes(b *testing.B) {
	dir := b.TempDir()
	path := filepath.Join(dir, "csr_attributes.yaml")
	var sb strings.Builder
	sb.WriteString("custom_attributes:\n  1.2.840.113549.1.9.7: \"secret\"\nextension_requests:\n")
	for i := range 100 {
		fmt.Fprintf(&sb, "  1.3.6.1.4.1.34380.1.2.%d: value-%d\n", i+1, i+1)
	}
	if err := os.WriteFile(path, []byte(sb.String()), 0o644); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		ext, custom, err := ParseCSRAttributes(path)
		if err != nil {
			b.Fatal(err)
		}
		if len(ext) != 100 || len(custom) != 1 {
			b.Fatalf("parsed extension/custom counts = %d/%d", len(ext), len(custom))
		}
	}
}
