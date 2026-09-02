package mitm

import (
	"crypto/x509"
	"net"
	"os"
	"path/filepath"
	"testing"
)

func TestGenerateCA(t *testing.T) {
	ca, err := GenerateCA("test-net-redirect")
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	leaf := ca.Certificate
	if !leaf.IsCA {
		t.Error("CA cert: IsCA = false, want true")
	}
	if leaf.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Error("CA cert missing CertSign key usage — cannot sign leaves")
	}
	if got := leaf.Subject.CommonName; got != "test-net-redirect CA" {
		t.Errorf("CommonName = %q, want %q", got, "test-net-redirect CA")
	}
	if _, err := ca.CertPool(); err != nil {
		t.Fatalf("CertPool: %v", err)
	}
}

func TestSignCertDomainAndVerify(t *testing.T) {
	ca, err := GenerateCA("test-ca")
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	pool, err := ca.CertPool()
	if err != nil {
		t.Fatalf("CertPool: %v", err)
	}

	cert, _, err := ca.SignCert("example.com")
	if err != nil {
		t.Fatalf("SignCert: %v", err)
	}
	if err := cert.VerifyHostname("example.com"); err != nil {
		t.Errorf("VerifyHostname(example.com): %v", err)
	}
	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:     pool,
		DNSName:   "example.com",
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Errorf("chain verify against CA pool: %v", err)
	}
	if cert.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Error("leaf missing DigitalSignature usage")
	}
	if cert.IsCA {
		t.Error("leaf marked as CA")
	}
}

func TestSignCertIPSAN(t *testing.T) {
	// The TProxy path signs certs for raw IPs — the SAN must be an IP address,
	// not a DNS name, or clients matching by IP fail.
	ca, err := GenerateCA("test-ca")
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	cert, _, err := ca.SignCert("127.0.0.1")
	if err != nil {
		t.Fatalf("SignCert(ip): %v", err)
	}
	if len(cert.IPAddresses) == 0 || !cert.IPAddresses[0].Equal(net.ParseIP("127.0.0.1")) {
		t.Fatalf("IPAddresses = %v, want 127.0.0.1 in SAN", cert.IPAddresses)
	}
	if len(cert.DNSNames) != 0 {
		t.Errorf("DNSNames = %v, want empty for an IP host", cert.DNSNames)
	}
	if err := cert.VerifyHostname("127.0.0.1"); err != nil {
		t.Errorf("VerifyHostname(127.0.0.1): %v", err)
	}
}

func TestSignCertExplicitSANs(t *testing.T) {
	ca, err := GenerateCA("test-ca")
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	cert, _, err := ca.SignCert("svc.internal", "svc.internal", "10.0.0.5")
	if err != nil {
		t.Fatalf("SignCert: %v", err)
	}
	if err := cert.VerifyHostname("svc.internal"); err != nil {
		t.Errorf("DNS SAN: %v", err)
	}
	if err := cert.VerifyHostname("10.0.0.5"); err != nil {
		t.Errorf("IP SAN: %v", err)
	}
}

func TestSaveAndLoadCA(t *testing.T) {
	dir := t.TempDir()
	base := filepath.Join(dir, "ca")

	ca, err := GenerateCA("roundtrip-ca")
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	if err := ca.SaveTo(base); err != nil {
		t.Fatalf("SaveTo: %v", err)
	}
	for _, suffix := range []string{".crt", ".key"} {
		if _, err := os.Stat(base + suffix); err != nil {
			t.Fatalf("SaveTo did not write %s: %v", suffix, err)
		}
	}

	loaded, err := LoadCA(base+".crt", base+".key")
	if err != nil {
		t.Fatalf("LoadCA: %v", err)
	}
	if !loaded.Certificate.Equal(ca.Certificate) {
		t.Error("LoadCA round-trip produced a different certificate")
	}
	if loaded.PrivateKey == nil {
		t.Error("LoadCA lost the private key")
	}
}

func TestLoadCARejectsGarbage(t *testing.T) {
	dir := t.TempDir()
	crt := filepath.Join(dir, "junk.crt")
	key := filepath.Join(dir, "junk.key")
	if err := os.WriteFile(crt, []byte("not pem at all"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, []byte("garbage"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCA(crt, key); err == nil {
		t.Fatal("LoadCA accepted garbage files, want error")
	}
}

func TestInterceptorCachesPerHost(t *testing.T) {
	ca, err := GenerateCA("ic-test")
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	ic := NewInterceptor(ca, t.TempDir())

	c1, err := ic.GetCertForHost("cached.example.com")
	if err != nil {
		t.Fatalf("GetCertForHost: %v", err)
	}
	c2, err := ic.GetCertForHost("cached.example.com")
	if err != nil {
		t.Fatalf("GetCertForHost second call: %v", err)
	}
	if len(c1.Certificate) == 0 || len(c2.Certificate) == 0 {
		t.Fatal("empty cert chain")
	}
	if string(c1.Certificate[0]) != string(c2.Certificate[0]) {
		t.Error("cache miss: same host returned different DER on second call")
	}
}

func TestInterceptorWildcardSANs(t *testing.T) {
	ca, err := GenerateCA("ic-test")
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	ic := NewInterceptor(ca, t.TempDir())

	wc, err := ic.GetCertForHost("*.wild.example.com")
	if err != nil {
		t.Fatalf("GetCertForHost(wildcard): %v", err)
	}
	cert, err := x509.ParseCertificate(wc.Certificate[0])
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}
	foundBare := false
	for _, dns := range cert.DNSNames {
		if dns == "wild.example.com" {
			foundBare = true
		}
	}
	if !foundBare {
		t.Errorf("wildcard cert SANs = %v, want bare domain present too", cert.DNSNames)
	}
}

func TestSSLGradeAndFingerprint(t *testing.T) {
	ca, err := GenerateCA("grade-test")
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}
	if g := SSLGrade(ca.Certificate); g != "CA" {
		t.Errorf("SSLGrade(CA) = %q, want %q", g, "CA")
	}
	leaf, _, err := ca.SignCert("graded.example.com")
	if err != nil {
		t.Fatalf("SignCert: %v", err)
	}
	if g := SSLGrade(leaf); g == "" || g == "CA" {
		t.Errorf("SSLGrade(leaf) = %q, want a letter grade", g)
	}
	fp := Fingerprint(leaf)
	if len(fp) != 64 {
		t.Errorf("Fingerprint length = %d, want 64 hex chars", len(fp))
	}
	if Fingerprint(nil) != "" {
		t.Error("Fingerprint(nil) should be empty string")
	}
}
