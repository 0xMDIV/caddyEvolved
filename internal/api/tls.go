package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

func (s *Server) certFile() string { return filepath.Join(s.Paths.Etc, "ui.crt") }
func (s *Server) keyFile() string  { return filepath.Join(s.Paths.Etc, "ui.key") }

// ensureCert returns a usable self-signed certificate, reusing an existing one
// while it has more than 30 days left.
func (s *Server) ensureCert() (certPEM, keyPEM []byte, err error) {
	certPEM, err = os.ReadFile(s.certFile())
	keyPEM, err2 := os.ReadFile(s.keyFile())
	if err == nil && err2 == nil {
		if valid, _ := usable(certPEM, keyPEM); valid {
			return certPEM, keyPEM, nil
		}
	}
	certPEM, keyPEM, err = s.generateCert()
	if err != nil {
		return nil, nil, err
	}
	if err := os.MkdirAll(s.Paths.Etc, 0o755); err != nil {
		return nil, nil, err
	}
	if err := os.WriteFile(s.keyFile(), keyPEM, 0o600); err != nil {
		return nil, nil, err
	}
	return certPEM, keyPEM, os.WriteFile(s.certFile(), certPEM, 0o644)
}

// usable checks parseability and remaining lifetime without importing a full
// verification chain.
func usable(certPEM, keyPEM []byte) (bool, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return false, fmt.Errorf("ui.crt: kein PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return false, err
	}
	if _, err := tls.X509KeyPair(certPEM, keyPEM); err != nil {
		return false, err
	}
	return time.Until(cert.NotAfter) > 30*24*time.Hour, nil
}

// generateCert creates an ECDSA P-256 self-signed cert valid for every local
// address of this host, so a LAN IP works without a hostname entry.
func (s *Server) generateCert() (certPEM, keyPEM []byte, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, err
	}
	tmpl := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "caddyforge", Organization: []string{"caddyforge"}},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           localAddresses(),
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, nil
}

// localAddresses lists this host's addresses for the certificate SANs.
func localAddresses() []net.IP {
	out := []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")}
	if ifaces, err := net.Interfaces(); err == nil {
		for _, ifi := range ifaces {
			if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
				continue
			}
			addrs, err := ifi.Addrs()
			if err != nil {
				continue
			}
			for _, a := range addrs {
				ipnet, ok := a.(*net.IPNet)
				if !ok {
					continue
				}
				if ipnet.IP.To4() != nil || ipnet.IP.Is6() {
					out = append(out, ipnet.IP)
				}
			}
		}
	}
	return out
}

// handleCert regenerates the self-signed certificate on demand (e.g. after the
// operator moved the container to a new IP).
func (s *Server) handleCert(w http.ResponseWriter, r *http.Request) {
	if _, _, err := s.generateAndStore(); err != nil {
		s.fail(w, r, err, 0)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"regenerated": true, "file": s.certFile()})
}

func (s *Server) generateAndStore() (string, error) {
	certPEM, _, err := s.ensureCert()
	if err != nil {
		return "", err
	}
	return string(certPEM), nil
}
