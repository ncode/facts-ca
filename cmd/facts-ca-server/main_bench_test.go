package main

import "testing"

func BenchmarkParseServeConfig(b *testing.B) {
	args := []string{
		"-cadir", "./cadir", "-listen", ":8140", "-hostname", "ca.example.com,127.0.0.1",
		"-ca-name", "bench-ca", "-init", "-autosign", "-allow-dns-alt-names", "-ttl", "24h",
	}
	b.ReportAllocs()
	for b.Loop() {
		cfg, err := parseServeConfig(args)
		if err != nil {
			b.Fatal(err)
		}
		if len(cfg.ca.Hostnames) != 2 {
			b.Fatalf("hostnames = %v", cfg.ca.Hostnames)
		}
	}
}
