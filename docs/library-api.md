# facts-ca as a toolkit — target shape

Synthesis of ADRs 0001–0009. This is the design to build against, not yet built.

## Package layout (one module, `github.com/ncode/facts-ca`)

```
pki/        (public)  X.509 primitives — keep current surface
agent/      (public)  enrollment + Identity (the "agent half")
ca/         (public)  embeddable CA (the "CA half")
internal/
  capi/     wire plumbing (paths, content-type, request building)
  ppext/    Puppet trusted-fact OIDs
  castore/  CA on-disk cadir store + signing  (used by ca/)
  ssldir/   agent ssldir store                (used by agent/)
  version/  build version
cmd/
  facts-ca-cli/     thin adapter over agent/ (+ admin client); CLI contract frozen
  facts-ca-server/  thin adapter over ca/;                      CLI contract frozen
```

Only `pki`, `agent`, `ca` are importable by other modules. Everything our own
binaries need from `internal/` they can still import (same module).

## Public API sketch

```go
// agent — the consumer/client half.
package agent

type Config struct {
    Server      string            // host:port of the CA
    Certname    string            // identity; defaults to FQDN
    Dir         string            // ssldir path; empty => ephemeral, in-memory (ADR 0006)
    KeyBits     int               // default 4096
    DNSAltNames []string
    Extensions  map[string]string // Puppet trusted facts: pp_role, pp_uuid, ... (or dotted OIDs)

    // Trust (ADR 0009): pin one, or opt into TOFU; never silently trusts.
    CACert          []byte // pinned CA PEM
    CAFingerprint   string // or accept a fetched CA only if it matches
    TrustOnFirstUse bool   // explicit fetch-and-trust

    WaitForCert time.Duration // 0 => single attempt
    Logger      *slog.Logger  // optional; default no-op (library never prints)
}

func Enroll(ctx context.Context, c Config) (*Identity, error)

type Identity struct{ /* holds current cert+key, pinned CA */ }

func (i *Identity) ClientTLSConfig(serverName string) *tls.Config // outbound mTLS
func (i *Identity) ServerTLSConfig() *tls.Config                  // inbound mTLS, RequireAndVerifyClientCert
func (i *Identity) HTTPClient() *http.Client
func (i *Identity) Listener(addr string) (net.Listener, error)
func (i *Identity) Certificate() tls.Certificate
func (i *Identity) CAPool() *x509.CertPool
func (i *Identity) Certname() string
// TLS configs use Get(Client)Certificate callbacks => renewal-ready (ADR 0005).

// ca — the embeddable CA half.
package ca

type Options struct {
    Dir         string // cadir (durable; required)
    CAName      string
    TTL         time.Duration
    AutosignAll bool
    AllowAltSAN bool
    Logger      *slog.Logger
}

func Init(o Options) (*CA, error) // create a new CA in Dir
func Open(o Options) (*CA, error) // load an existing CA

func (c *CA) Handler() http.Handler        // mount the Puppet CA v1 routes
func (c *CA) ServerTLSConfig() *tls.Config // verify-if-given (agents bootstrap without a cert)
func (c *CA) ListenAndServe(addr string) error
func (c *CA) Sign(name string, o pki.SignOpts) error
func (c *CA) Revoke(name string) error
func (c *CA) Clean(name string) error
func (c *CA) Statuses() ([]Status, error)  // Status is public here, not an internal type
```

## A consumer service, both halves

```go
// Inbound + outbound mTLS for "payments-api", zero Puppet knowledge:
id, err := agent.Enroll(ctx, agent.Config{
    Server: "ca.internal:8140", Certname: "payments-api.prod",
    CAFingerprint: pinned, // production pins the CA
})
srv := &http.Server{Addr: ":8443", TLSConfig: id.ServerTLSConfig(), Handler: mux}
out := id.HTTPClient() // calls to other mesh services are mutually authenticated

// Embed a CA beside your own routes:
c, _ := ca.Open(ca.Options{Dir: "/var/lib/myca"})
mux.Handle("/puppet-ca/v1/", c.Handler())
```

## Migration map (where today's code goes)

- `cmd/facts-ca-cli/main.go` enrollment + mTLS builders  → `agent/`
- `cmd/facts-ca-server/main.go` handlers + TLS + serving → `ca/`
- `internal/pki` → `pki/` (made public)
- `internal/{capi,ppext,castore,ssldir,version}` → stay `internal/`
- Wire DTOs that surface in public signatures (cert status, desired-state) are
  re-homed public (in `ca`/`agent`), since public methods can't expose internal
  types.

## Defaults folded in (veto any)

- **Name**: keep `github.com/ncode/facts-ca`; packages `agent`, `ca`, `pki`.
  Importing `facts-ca/agent` reads fine and avoids renaming the repo/remote/CI.
- **Versioning**: start v0.x, "API unstable until v1" (ADR 0008).
- **Logging**: library returns errors and takes an optional `*slog.Logger`
  (default no-op); it never prints. The binaries do all user-facing output.
- **CA durability**: `ca` stays disk-backed; the per-process mutex + unlocked
  `serial` file remain a documented single-writer limitation (multi-replica CA
  is out of scope until real).
```
