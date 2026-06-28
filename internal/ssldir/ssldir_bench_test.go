package ssldir

import (
	"fmt"
	"testing"
)

func BenchmarkLoadOrCreateKey(b *testing.B) {
	b.Run("fresh", func(b *testing.B) {
		dir := b.TempDir()
		b.ReportAllocs()
		i := 0
		for b.Loop() {
			ssl := New(dir, fmt.Sprintf("node-%d", i))
			i++
			key, err := ssl.LoadOrCreateKey(2048)
			if err != nil {
				b.Fatal(err)
			}
			if key.N.Sign() == 0 {
				b.Fatal("empty key")
			}
		}
	})
	b.Run("reuse", func(b *testing.B) {
		ssl := New(b.TempDir(), "node")
		if _, err := ssl.LoadOrCreateKey(2048); err != nil {
			b.Fatal(err)
		}
		b.ReportAllocs()
		for b.Loop() {
			key, err := ssl.LoadOrCreateKey(2048)
			if err != nil {
				b.Fatal(err)
			}
			if key.N.Sign() == 0 {
				b.Fatal("empty key")
			}
		}
	})
}
