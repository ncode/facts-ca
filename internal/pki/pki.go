// Package pki holds the X.509 primitives shared by the facts-ca client and
// server: key generation, CSR creation, CA signing, CRLs, PEM I/O and the
// fingerprint format Puppet exposes over its CA API.
//
// Encodings are chosen to byte-match what OpenSSL/Puppet write so the files
// drop into a real Puppet ssldir/cadir unchanged:
//   - RSA private keys: PKCS#1 ("RSA PRIVATE KEY")
//   - public keys:      PKIX/SPKI ("PUBLIC KEY")
//   - certs/CSR/CRL:    standard PEM blocks
package pki

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"
)

// DefaultKeyBits matches Puppet's default `keylength`.
const DefaultKeyBits = 4096

// DefaultCATTL matches Puppet's default `ca_ttl` (5 years) for issued certs.
const DefaultCATTL = 5 * 365 * 24 * time.Hour

// GenerateKey returns a fresh RSA key. bits<=0 uses DefaultKeyBits.
func GenerateKey(bits int) (*rsa.PrivateKey, error) {
	if bits <= 0 {
		bits = DefaultKeyBits
	}
	return rsa.GenerateKey(rand.Reader, bits)
}

// CreateCSR builds a PEM CSR for certname. dnsAltNames, when non-empty, become
// subjectAltName entries (Puppet always includes the certname itself as a DNS
// SAN when any alt names are requested). extraExts are added as CSR extension
// requests (Puppet's extension_requests / trusted-fact OIDs).
func CreateCSR(key *rsa.PrivateKey, certname string, dnsAltNames []string, extraExts []pkix.Extension) ([]byte, error) {
	tmpl := &x509.CertificateRequest{
		Subject:            pkix.Name{CommonName: certname},
		SignatureAlgorithm: x509.SHA256WithRSA,
		ExtraExtensions:    extraExts,
	}
	if len(dnsAltNames) > 0 {
		seen := map[string]bool{}
		add := func(n string) {
			n = strings.TrimSpace(n)
			if n == "" || seen[n] {
				return
			}
			seen[n] = true
			if ip := net.ParseIP(n); ip != nil {
				tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
			} else {
				tmpl.DNSNames = append(tmpl.DNSNames, n)
			}
		}
		add(certname)
		for _, n := range dnsAltNames {
			add(n)
		}
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

// CAName is the conventional Puppet CA subject ("Puppet CA: <name>").
func CAName(name string) pkix.Name { return pkix.Name{CommonName: "Puppet CA: " + name} }

// CreateCA self-signs a CA certificate + key. ttl<=0 defaults to 10 years
// (a CA outliving the 5y leaf default avoids the classic Puppet CA-expiry trap).
func CreateCA(name string, bits int, ttl time.Duration) (*rsa.PrivateKey, *x509.Certificate, error) {
	if ttl <= 0 {
		ttl = 10 * 365 * 24 * time.Hour
	}
	key, err := GenerateKey(bits)
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               CAName(name),
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(ttl),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
	}
	setSKI(tmpl, &key.PublicKey)
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	crt, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return key, crt, nil
}

// SignOpts controls how a CSR is turned into a leaf certificate.
type SignOpts struct {
	Serial          *big.Int
	TTL             time.Duration    // <=0 => DefaultCATTL
	DNSAltNames     []string         // extra SANs to honor from the CSR/request
	AllowAltSAN     bool             // honor SANs present in the CSR
	ExtraExtensions []pkix.Extension // Puppet trusted-fact extensions to embed
}

// SignCSR issues a leaf cert for csr, signed by (caKey, caCrt).
func SignCSR(csr *x509.CertificateRequest, caCrt *x509.Certificate, caKey *rsa.PrivateKey, opts SignOpts) (*x509.Certificate, error) {
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("csr signature invalid: %w", err)
	}
	ttl := opts.TTL
	if ttl <= 0 {
		ttl = DefaultCATTL
	}
	serial := opts.Serial
	if serial == nil {
		// No serial supplied: random 128-bit serial so callers can't mint
		// duplicate serials (which would break revocation/tracking).
		var err error
		if serial, err = rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128)); err != nil {
			return nil, err
		}
		serial.Add(serial, big.NewInt(1)) // keep it positive and non-zero
	}
	now := time.Now()
	notAfter := now.Add(ttl)
	if caCrt != nil && notAfter.After(caCrt.NotAfter) {
		notAfter = caCrt.NotAfter // a leaf must never outlive its issuer
	}
	tmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: csr.Subject.CommonName},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	// SANs: honor CSR-embedded ones (if allowed) plus any operator-supplied.
	dns := map[string]bool{}
	var ips []net.IP
	addName := func(n string) {
		n = strings.TrimSpace(n)
		if n == "" {
			return
		}
		if ip := net.ParseIP(n); ip != nil {
			ips = append(ips, ip)
		} else if !dns[n] {
			dns[n] = true
			tmpl.DNSNames = append(tmpl.DNSNames, n)
		}
	}
	if opts.AllowAltSAN {
		for _, n := range csr.DNSNames {
			addName(n)
		}
		ips = append(ips, csr.IPAddresses...)
	}
	for _, n := range opts.DNSAltNames {
		addName(n)
	}
	if len(tmpl.DNSNames) > 0 || len(ips) > 0 {
		addName(csr.Subject.CommonName) // certname is always a SAN when SANs exist
		tmpl.IPAddresses = ips
	}
	pub, ok := csr.PublicKey.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("only RSA CSRs are supported")
	}
	setSKI(tmpl, pub)
	tmpl.ExtraExtensions = opts.ExtraExtensions // Puppet trusted-fact extensions
	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCrt, pub, caKey)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// RevokedEntry is one revoked serial for CRL generation.
type RevokedEntry struct {
	Serial *big.Int
	When   time.Time
}

// CreateCRL builds a PEM CRL signed by the CA, valid for the given window.
func CreateCRL(caCrt *x509.Certificate, caKey *rsa.PrivateKey, revoked []RevokedEntry, validFor time.Duration) ([]byte, error) {
	if validFor <= 0 {
		validFor = 24 * time.Hour
	}
	list := make([]x509.RevocationListEntry, 0, len(revoked))
	for _, r := range revoked {
		list = append(list, x509.RevocationListEntry{SerialNumber: r.Serial, RevocationTime: r.When})
	}
	now := time.Now()
	tmpl := &x509.RevocationList{
		Number:                    big.NewInt(now.Unix()),
		ThisUpdate:                now.Add(-time.Hour),
		NextUpdate:                now.Add(validFor),
		RevokedCertificateEntries: list,
	}
	der, err := x509.CreateRevocationList(rand.Reader, tmpl, caCrt, caKey)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: der}), nil
}

// --- fingerprints ---------------------------------------------------------

// Fingerprints returns the digest map Puppet exposes (uppercase hex, colon
// separated). The "default" / top-level fingerprint is SHA256.
func Fingerprints(certDER []byte) map[string]string {
	s1 := sha1.Sum(certDER)
	s256 := sha256.Sum256(certDER)
	return map[string]string{
		"SHA1":    colonHex(s1[:]),
		"SHA256":  colonHex(s256[:]),
		"default": colonHex(s256[:]),
	}
}

func colonHex(b []byte) string {
	h := strings.ToUpper(hex.EncodeToString(b))
	var sb strings.Builder
	for i := 0; i < len(h); i += 2 {
		if i > 0 {
			sb.WriteByte(':')
		}
		sb.WriteString(h[i : i+2])
	}
	return sb.String()
}

// --- PEM I/O --------------------------------------------------------------

func EncodePrivateKey(key *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
}

func EncodePublicKey(key *rsa.PrivateKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

func EncodeCert(crt *x509.Certificate) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: crt.Raw})
}

func DecodePrivateKey(b []byte) (*rsa.PrivateKey, error) {
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("no PEM private key found")
	}
	if k, err := x509.ParsePKCS1PrivateKey(blk.Bytes); err == nil {
		return k, nil
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, err
	}
	rk, ok := k.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("private key is not RSA")
	}
	return rk, nil
}

func DecodeCert(b []byte) (*x509.Certificate, error) {
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("no PEM certificate found")
	}
	return x509.ParseCertificate(blk.Bytes)
}

func DecodeCSR(b []byte) (*x509.CertificateRequest, error) {
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("no PEM certificate request found")
	}
	return x509.ParseCertificateRequest(blk.Bytes)
}

// setSKI sets the subjectKeyId to the SHA-1 of the SPKI, matching the common
// RFC 5280 method OpenSSL/Puppet use.
func setSKI(tmpl *x509.Certificate, pub *rsa.PublicKey) {
	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return
	}
	var info struct {
		Algorithm        pkix.AlgorithmIdentifier
		SubjectPublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(spki, &info); err != nil {
		return
	}
	sum := sha1.Sum(info.SubjectPublicKey.Bytes)
	tmpl.SubjectKeyId = sum[:]
}
