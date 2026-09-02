package mitm

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

type CACert struct {
	Certificate *x509.Certificate
	PrivateKey  crypto.PrivateKey
	PEMCert     []byte
	PEMKey      []byte
}

func GenerateCA(name string) (*CACert, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: name + " CA", Organization: []string{name}},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return nil, fmt.Errorf("create ca: %w", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, fmt.Errorf("parse ca: %w", err)
	}
	pemCert := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	privBytes, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("marshal key: %w", err)
	}
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: privBytes})
	return &CACert{Certificate: cert, PrivateKey: priv, PEMCert: pemCert, PEMKey: pemKey}, nil
}

func LoadCA(certPath, keyPath string) (*CACert, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, fmt.Errorf("read cert: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, fmt.Errorf("read key: %w", err)
	}
	certBlock, _ := pem.Decode(certPEM)
	if certBlock == nil {
		return nil, fmt.Errorf("decode cert pem")
	}
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse cert: %w", err)
	}
	keyBlock, _ := pem.Decode(keyPEM)
	if keyBlock == nil {
		return nil, fmt.Errorf("decode key pem")
	}
	var priv crypto.PrivateKey
	if keyBlock.Type == "EC PRIVATE KEY" {
		priv, err = x509.ParseECPrivateKey(keyBlock.Bytes)
	} else {
		priv, err = x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	}
	if err != nil {
		return nil, fmt.Errorf("parse key: %w", err)
	}
	return &CACert{Certificate: cert, PrivateKey: priv, PEMCert: certPEM, PEMKey: keyPEM}, nil
}

func (c *CACert) SaveTo(path string) error {
	if err := os.WriteFile(path+".crt", c.PEMCert, 0644); err != nil {
		return err
	}
	return os.WriteFile(path+".key", c.PEMKey, 0600)
}

// CertPool returns an x509 pool containing this CA as a trusted root, so
// clients (and tests) can verify leaf certs signed by it.
func (c *CACert) CertPool() (*x509.CertPool, error) {
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(c.PEMCert) {
		return nil, fmt.Errorf("CA PEM could not be added to cert pool")
	}
	return pool, nil
}

// SignCert signs a leaf certificate for commonName with the given SANs. An
// empty sans list falls back to commonName itself as the sole SAN, inferred as
// an IP address or DNS name.
func (c *CACert) SignCert(commonName string, sans ...string) (cert *x509.Certificate, privKey crypto.PrivateKey, err error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate leaf key: %w", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName, Organization: []string{"net-redirect"}},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	for _, san := range sans {
		san = strings.TrimSpace(san)
		if san == "" {
			continue
		}
		if ip := net.ParseIP(san); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, san)
		}
	}
	if len(template.DNSNames) == 0 && len(template.IPAddresses) == 0 {
		if ip := net.ParseIP(commonName); ip != nil {
			template.IPAddresses = append(template.IPAddresses, ip)
		} else {
			template.DNSNames = append(template.DNSNames, commonName)
		}
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, c.Certificate, &priv.PublicKey, c.PrivateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("create leaf: %w", err)
	}
	cert, err = x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("parse leaf: %w", err)
	}
	return cert, priv, nil
}

type Interceptor struct {
	ca        *CACert
	certCache sync.Map
	certDir   string
}

func NewInterceptor(ca *CACert, certDir string) *Interceptor {
	return &Interceptor{ca: ca, certDir: certDir}
}

func (i *Interceptor) GetCertForHost(host string) (tls.Certificate, error) {
	if cached, ok := i.certCache.Load(host); ok {
		return cached.(tls.Certificate), nil
	}
	sans := []string{host}
	if strings.HasPrefix(host, "*.") {
		sans = append(sans, host[2:])
	}
	cn := host
	if strings.HasPrefix(cn, "*.") {
		cn = cn[2:]
	}
	cert, priv, err := i.ca.SignCert(cn, sans...)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("sign cert for %s: %w", host, err)
	}
	tlsCert := tls.Certificate{
		Certificate: [][]byte{cert.Raw},
		PrivateKey:  priv,
		Leaf:        cert,
	}
	i.certCache.Store(host, tlsCert)
	return tlsCert, nil
}

func SSLGrade(cert *x509.Certificate) string {
	if cert == nil {
		return "N/A"
	}
	if cert.IsCA {
		return "CA"
	}
	switch key := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		if key.N.BitLen() >= 4096 {
			return "A+"
		}
		if key.N.BitLen() >= 2048 {
			return "A"
		}
		return "B"
	case *ecdsa.PublicKey:
		return "A"
	default:
		return "B"
	}
}

func Fingerprint(cert *x509.Certificate) string {
	if cert == nil {
		return ""
	}
	h := sha256.Sum256(cert.Raw)
	return fmt.Sprintf("%x", h)
}