package pki

import (
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
)

func TestCAPersistsAcrossLoads(t *testing.T) {
	dir := t.TempDir()
	ca1, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	ca2, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	if ca1.Pin() != ca2.Pin() {
		t.Fatal("CA pin changed between loads")
	}
	info, err := os.Stat(filepath.Join(dir, caKeyFile))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("CA key mode = %v, want 0600", info.Mode().Perm())
	}
}

func TestServerCertificateReissuedWhenHostsChange(t *testing.T) {
	dir := t.TempDir()
	ca, err := LoadOrCreateCA(dir)
	if err != nil {
		t.Fatal(err)
	}
	c1, err := ca.ServerCertificate(dir, []string{"dockgate.example.net", "192.0.2.10"})
	if err != nil {
		t.Fatal(err)
	}
	c2, err := ca.ServerCertificate(dir, []string{"192.0.2.10", "dockgate.example.net"})
	if err != nil {
		t.Fatal(err)
	}
	if c1.Leaf.SerialNumber.Cmp(c2.Leaf.SerialNumber) != 0 {
		t.Fatal("certificate reissued although hosts are unchanged")
	}
	c3, err := ca.ServerCertificate(dir, []string{"dockgate.example.net"})
	if err != nil {
		t.Fatal(err)
	}
	if c3.Leaf.SerialNumber.Cmp(c1.Leaf.SerialNumber) == 0 {
		t.Fatal("certificate not reissued after hosts changed")
	}
	if _, err := c3.Leaf.Verify(x509.VerifyOptions{DNSName: "dockgate.example.net", Roots: ca.Pool()}); err != nil {
		t.Fatalf("server certificate does not verify: %v", err)
	}
}

func TestSignAgentPinMatchesKey(t *testing.T) {
	ca, err := LoadOrCreateCA(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	key, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	csr, err := NewCSR(key, "alpha")
	if err != nil {
		t.Fatal(err)
	}
	_, cert, err := ca.SignAgent(csr, "agt_1")
	if err != nil {
		t.Fatal(err)
	}
	want, err := PublicKeyPin(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	if Pin(cert) != want {
		t.Fatal("certificate pin differs from key pin")
	}
	if cert.Subject.CommonName != "agt_1" {
		t.Fatalf("CN = %q, want agent ID", cert.Subject.CommonName)
	}
	if _, err := cert.Verify(x509.VerifyOptions{Roots: ca.Pool(), KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("agent certificate does not verify for client auth: %v", err)
	}
}

func TestParseCSRRejectsGarbage(t *testing.T) {
	if _, err := ParseCSR([]byte("not a csr")); err == nil {
		t.Fatal("ParseCSR accepted garbage")
	}
}
