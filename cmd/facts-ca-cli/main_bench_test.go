package main

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func BenchmarkParseCommon(b *testing.B) {
	args := []string{
		"bootstrap", "--server", "ca.example.com", "--certname=node.example",
		"--ssldir", "./ssl", "--waitforcert", "30s", "--onetime",
		"--ext", "pp_role=web", "--ext=pp_authorization=true",
	}
	b.ReportAllocs()
	for b.Loop() {
		opts, pos := parseCommon(args)
		if opts["server"] == "" || len(pos) != 1 {
			b.Fatalf("opts=%v pos=%v", opts, pos)
		}
	}
}

func BenchmarkResolveCommon(b *testing.B) {
	dir := b.TempDir()
	certs := filepath.Join(dir, "certs")
	if err := os.MkdirAll(certs, 0o755); err != nil {
		b.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(certs, "node.example.pem"), []byte("cert"), 0o644); err != nil {
		b.Fatal(err)
	}
	opts := map[string]string{"server": "ca.example.com", "ssldir": dir}
	b.ReportAllocs()
	for b.Loop() {
		c, err := resolveCommon(opts)
		if err != nil {
			b.Fatal(err)
		}
		if c.certname != "node.example" {
			b.Fatalf("certname = %q", c.certname)
		}
	}
}

func BenchmarkDiscoverCertname(b *testing.B) {
	dir := b.TempDir()
	certs := filepath.Join(dir, "certs")
	if err := os.MkdirAll(certs, 0o755); err != nil {
		b.Fatal(err)
	}
	for i := range 100 {
		if err := os.WriteFile(filepath.Join(certs, fmt.Sprintf("node-%03d.txt", i)), []byte("x"), 0o644); err != nil {
			b.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(certs, "node.example.pem"), []byte("cert"), 0o644); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	for b.Loop() {
		if got := discoverCertname(dir); got != "node.example" {
			b.Fatalf("discoverCertname = %q", got)
		}
	}
}

func BenchmarkSmallUtils(b *testing.B) {
	b.Run("split-comma", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if len(splitComma("a,b, c,,d")) != 4 {
				b.Fatal("bad split")
			}
		}
	})
	b.Run("atoi-or", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if atoiOr("4096", 2048) != 4096 {
				b.Fatal("bad int")
			}
		}
	})
	b.Run("duration-or", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			if durationOr("30s", time.Second) != 30*time.Second {
				b.Fatal("bad duration")
			}
		}
	})
}
