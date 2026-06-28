package agent

import (
	"context"
	"fmt"
	"testing"
)

func BenchmarkEnroll(b *testing.B) {
	b.Run("ephemeral-autosign", func(b *testing.B) {
		server, _ := caServer(b, true, true)
		i := 0
		b.ReportAllocs()
		for b.Loop() {
			id, err := Enroll(context.Background(), Config{
				Server: server, Certname: fmt.Sprintf("node-%d", i),
				KeyBits: 2048, DNSAltNames: []string{"127.0.0.1"}, TrustOnFirstUse: true,
			})
			i++
			if err != nil {
				b.Fatal(err)
			}
			if id.Certificate().Leaf == nil {
				b.Fatal("missing leaf")
			}
		}
	})
	b.Run("load-from-disk", func(b *testing.B) {
		server, _ := caServer(b, true, false)
		dir := b.TempDir()
		if _, err := Enroll(context.Background(), Config{
			Server: server, Certname: "disk-node", Dir: dir,
			KeyBits: 2048, TrustOnFirstUse: true,
		}); err != nil {
			b.Fatal(err)
		}
		b.ReportAllocs()
		for b.Loop() {
			id, err := Load(dir, "disk-node")
			if err != nil {
				b.Fatal(err)
			}
			if id.Certificate().Leaf == nil {
				b.Fatal("missing leaf")
			}
		}
	})
}

func BenchmarkIdentity(b *testing.B) {
	server, _ := caServer(b, true, false)
	id, err := Enroll(context.Background(), Config{Server: server, Certname: "identity", KeyBits: 2048, TrustOnFirstUse: true})
	if err != nil {
		b.Fatal(err)
	}
	b.Run("client-tls-config", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			cfg := id.ClientTLSConfig("127.0.0.1")
			if cfg.RootCAs == nil {
				b.Fatal("missing root pool")
			}
		}
	})
	b.Run("http-client", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			c := id.HTTPClient()
			if c.Transport == nil {
				b.Fatal("missing transport")
			}
		}
	})
}
