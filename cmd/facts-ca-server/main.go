// facts-ca-server is a Go port of the Puppet CA service. It is a thin adapter
// over the ca package: it speaks the Puppet CA v1 HTTP API over mTLS so real
// Puppet agents (and facts-ca-cli) can bootstrap certificates against it, and
// offers offline list/sign/revoke/clean against the cadir.
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/ncode/facts-ca/ca"
	"github.com/ncode/facts-ca/internal/version"
	"github.com/ncode/facts-ca/pki"
)

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version", "--version", "-v":
			fmt.Println(version.Version)
			return
		case "sign", "revoke", "list", "clean":
			adminMain(os.Args[1], os.Args[2:])
			return
		}
	}
	serveMain()
}

// adminMain implements the offline CA operations (`facts-ca-server sign NODE`,
// the equivalent of `puppetserver ca sign`), acting directly on the cadir.
func adminMain(action string, args []string) {
	fs := flag.NewFlagSet(action, flag.ExitOnError)
	cadir := fs.String("cadir", "./cadir", "CA state directory")
	ttl := fs.Duration("ttl", pki.DefaultCATTL, "lifetime of issued certificates (sign only)")
	_ = fs.Parse(args)

	c, err := ca.Open(ca.Options{Dir: *cadir, TTL: *ttl})
	if err != nil {
		fatal("open CA: %v", err)
	}
	switch action {
	case "list":
		list, err := c.Statuses()
		if err != nil {
			fatal("list: %v", err)
		}
		for _, s := range list {
			fmt.Printf("%-40s %-10s %s\n", s.Name, s.State, s.Fingerprint)
		}
	case "sign", "revoke", "clean":
		name := fs.Arg(0)
		if name == "" {
			fatal("usage: facts-ca-server %s <certname>", action)
		}
		switch action {
		case "sign":
			err = c.Sign(name, pki.SignOpts{})
		case "revoke":
			err = c.Revoke(name)
		case "clean":
			_ = c.Revoke(name)
			err = c.Clean(name)
		}
		if err != nil {
			fatal("%s %s: %v", action, name, err)
		}
		fmt.Printf("%s: %s\n", name, action+"d")
	}
}

func serveMain() {
	var (
		cadir    = flag.String("cadir", "./cadir", "CA state directory (puppetserver cadir layout)")
		listen   = flag.String("listen", ":8140", "HTTPS listen address (Puppet uses 8140)")
		hostname = flag.String("hostname", defaultHostname(), "server FQDN(s), comma-separated, for its TLS cert")
		caName   = flag.String("ca-name", "", "CA subject name (default: first hostname)")
		doInit   = flag.Bool("init", false, "initialize the CA in -cadir if absent")
		autosign = flag.Bool("autosign", false, "auto-sign every incoming CSR (insecure)")
		ttl      = flag.Duration("ttl", pki.DefaultCATTL, "lifetime of issued certificates")
		altSAN   = flag.Bool("allow-dns-alt-names", false, "honor subjectAltNames in agent CSRs (puppetserver default: off)")
	)
	flag.Parse()

	hostnames := splitComma(*hostname)
	if len(hostnames) == 0 {
		fatal("-hostname must contain at least one non-empty hostname")
	}
	opts := ca.Options{
		Dir:         *cadir,
		CAName:      *caName,
		Hostnames:   hostnames,
		TTL:         *ttl,
		AutosignAll: *autosign,
		AllowAltSAN: *altSAN,
		Logger:      slog.Default(),
	}

	c, err := ca.Open(opts)
	if ca.IsNotExist(err) {
		if !*doInit {
			fatal("no CA at %s (pass -init to create one): %v", *cadir, err)
		}
		c, err = ca.Init(opts)
		if err != nil {
			fatal("init CA: %v", err)
		}
		name := *caName
		if name == "" {
			name = hostnames[0]
		}
		slog.Info("initialized CA", "dir", *cadir, "name", name)
	} else if err != nil {
		fatal("open CA: %v", err)
	}

	slog.Info("facts-ca-server listening", "addr", *listen, "autosign", *autosign)
	if err := c.ListenAndServe(*listen); err != nil {
		fatal("serve: %v", err)
	}
}

func splitComma(s string) []string {
	var out []string
	for p := range strings.SplitSeq(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func defaultHostname() string {
	h, err := os.Hostname()
	if err != nil || h == "" {
		return "localhost"
	}
	return h
}

func fatal(format string, args ...any) {
	slog.Error(fmt.Sprintf(format, args...))
	os.Exit(1)
}
