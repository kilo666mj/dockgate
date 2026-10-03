// Package pki holds dockgate's private certificate authority: it issues the
// server's TLS certificate and the agents' client certificates, and computes
// the public key pins used for enrollment and agent identity.
package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"time"
)

// Certificate lifetimes.
const (
	CALifetime     = 10 * 365 * 24 * time.Hour
	ServerLifetime = 90 * 24 * time.Hour
	AgentLifetime  = 90 * 24 * time.Hour
	// RenewBefore is how long before expiry a certificate is replaced.
	RenewBefore = 30 * 24 * time.Hour
)

const (
	caCertFile     = "ca.crt"
	caKeyFile      = "ca.key"
	serverCertFile = "server.crt"
	serverKeyFile  = "server.key"
)

// CA is a loaded certificate authority.
type CA struct {
	Cert *x509.Certificate
	key  crypto.Signer
	PEM  []byte
}

// LoadOrCreateCA loads the CA from dir, creating it on first use.
func LoadOrCreateCA(dir string) (*CA, error) {
	certPath := filepath.Join(dir, caCertFile)
	keyPath := filepath.Join(dir, caKeyFile)
	if _, err := os.Stat(certPath); errors.Is(err, os.ErrNotExist) {
		if err := createCA(certPath, keyPath); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	cert, err := ParseCertificatePEM(certPEM)
	if err != nil {
		return nil, fmt.Errorf("CA certificate: %w", err)
	}
	key, err := ReadKey(keyPath)
	if err != nil {
		return nil, fmt.Errorf("CA key: %w", err)
	}
	return &CA{Cert: cert, key: key, PEM: certPEM}, nil
}

func createCA(certPath, keyPath string) error {
	key, err := NewKey()
	if err != nil {
		return err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber:          randomSerial(),
		Subject:               pkix.Name{CommonName: "dockgate CA"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(CALifetime),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return err
	}
	if err := WriteKey(keyPath, key); err != nil {
		return err
	}
	return WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
}

// Pin returns the CA's public key pin.
func (ca *CA) Pin() string { return Pin(ca.Cert) }

// Pool returns a certificate pool containing only this CA.
func (ca *CA) Pool() *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(ca.Cert)
	return pool
}

// ServerCertificate returns the server's TLS certificate for the given DNS
// names and IP addresses, reissuing it when it is missing, near expiry, or
// does not cover exactly those names.
func (ca *CA) ServerCertificate(dir string, hosts []string) (tls.Certificate, error) {
	certPath := filepath.Join(dir, serverCertFile)
	keyPath := filepath.Join(dir, serverKeyFile)
	if cert, err := tls.LoadX509KeyPair(certPath, keyPath); err == nil {
		if leaf := cert.Leaf; leaf != nil && ca.issued(leaf) && coversExactly(leaf, hosts) &&
			time.Until(leaf.NotAfter) > RenewBefore {
			return cert, nil
		}
	}
	key, err := NewKey()
	if err != nil {
		return tls.Certificate{}, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: randomSerial(),
		Subject:      pkix.Name{CommonName: "dockgate server"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(ServerLifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, key.Public(), ca.key)
	if err != nil {
		return tls.Certificate{}, err
	}
	if err := WriteKey(keyPath, key); err != nil {
		return tls.Certificate{}, err
	}
	if err := WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return tls.Certificate{}, err
	}
	return tls.LoadX509KeyPair(certPath, keyPath)
}

func (ca *CA) issued(cert *x509.Certificate) bool {
	return cert.CheckSignatureFrom(ca.Cert) == nil
}

func coversExactly(cert *x509.Certificate, hosts []string) bool {
	var have []string
	have = append(have, cert.DNSNames...)
	for _, ip := range cert.IPAddresses {
		have = append(have, ip.String())
	}
	want := make([]string, 0, len(hosts))
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			h = ip.String()
		}
		want = append(want, h)
	}
	slices.Sort(have)
	slices.Sort(want)
	return slices.Equal(have, want)
}

// SignAgent issues a client certificate for the public key in csrPEM. The
// agent ID becomes the certificate's common name.
func (ca *CA) SignAgent(csrPEM []byte, agentID string) ([]byte, *x509.Certificate, error) {
	csr, err := ParseCSR(csrPEM)
	if err != nil {
		return nil, nil, err
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: randomSerial(),
		Subject:      pkix.Name{CommonName: agentID},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(AgentLifetime),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.Cert, csr.PublicKey, ca.key)
	if err != nil {
		return nil, nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), cert, nil
}

// ParseCSR decodes a PEM certificate request and checks its signature, which
// proves the requester holds the private key.
func ParseCSR(csrPEM []byte) (*x509.CertificateRequest, error) {
	block, _ := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, errors.New("CSR: no CERTIFICATE REQUEST PEM block")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR signature: %w", err)
	}
	return csr, nil
}

// NewCSR returns a PEM certificate request for key.
func NewCSR(key crypto.Signer, commonName string) ([]byte, error) {
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: commonName},
	}, key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: der}), nil
}

// Pin returns the lowercase hex SHA-256 of a certificate's
// SubjectPublicKeyInfo. Pins survive certificate renewal with the same key.
func Pin(cert *x509.Certificate) string {
	sum := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:])
}

// PublicKeyPin returns the pin for a bare public key.
func PublicKeyPin(pub crypto.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return hex.EncodeToString(sum[:]), nil
}

// ParseCertificatePEM decodes the first certificate in data.
func ParseCertificatePEM(data []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("no CERTIFICATE PEM block")
	}
	return x509.ParseCertificate(block.Bytes)
}

// NewKey generates an ECDSA P-256 key.
func NewKey() (*ecdsa.PrivateKey, error) {
	return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
}

// WriteKey writes key as a PKCS#8 PEM file readable only by its owner.
func WriteKey(path string, key crypto.Signer) error {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return err
	}
	return WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0o600)
}

// ReadKey reads a PKCS#8 PEM private key.
func ReadKey(path string) (crypto.Signer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, errors.New("no PRIVATE KEY PEM block")
	}
	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, errors.New("private key cannot sign")
	}
	return signer, nil
}

// WriteFile replaces path atomically so a crash never leaves a truncated
// key or certificate behind.
func WriteFile(path string, data []byte, perm os.FileMode) (err error) {
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	defer func() {
		if err != nil {
			_ = os.Remove(tmp.Name())
		}
	}()
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

func randomSerial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		// crypto/rand does not fail on supported platforms.
		panic(err)
	}
	return n
}
