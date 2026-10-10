// Package certs reads the certificates caddy manages from its storage.
//
// Caddy's admin API lists only its internal CA, not the ACME certificates, so
// the storage layout is the source: certificates/<issuer-key>/<name>/<name>.crt
// next to a .key and a .json sidecar.
package certs

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// Cert is one leaf certificate on disk.
type Cert struct {
	Name      string    `json:"name"` // storage name, e.g. "wildcard_.example.com"
	Domains   []string  `json:"domains"`
	Issuer    string    `json:"issuer"`    // issuer CN, e.g. "R11"
	IssuerKey string    `json:"issuerKey"` // storage dir, e.g. "acme-v02.api.letsencrypt.org-directory"
	Source    string    `json:"source"`    // letsencrypt | zerossl | internal | other
	Staging   bool      `json:"staging"`
	NotBefore time.Time `json:"notBefore"`
	NotAfter  time.Time `json:"notAfter"`
	DaysLeft  int       `json:"daysLeft"`
	// HoursLeft matters for the internal CA, whose leaves live 12 hours.
	HoursLeft int    `json:"hoursLeft"`
	Serial    string `json:"serial"`
	KeyType   string `json:"keyType"`
}

// List walks <storage>/certificates. A missing directory is an empty list:
// caddy creates it on the first issuance.
func List(storage string) ([]Cert, error) {
	root := filepath.Join(storage, "certificates")
	issuers, err := os.ReadDir(root)
	if os.IsNotExist(err) {
		return []Cert{}, nil
	}
	if err != nil {
		return nil, err
	}
	out := []Cert{}
	for _, iss := range issuers {
		if !iss.IsDir() {
			continue
		}
		names, err := os.ReadDir(filepath.Join(root, iss.Name()))
		if err != nil {
			continue
		}
		for _, n := range names {
			if !n.IsDir() {
				continue
			}
			path := filepath.Join(root, iss.Name(), n.Name(), n.Name()+".crt")
			c, err := parse(path)
			if err != nil {
				continue
			}
			c.Name, c.IssuerKey = n.Name(), iss.Name()
			c.Source, c.Staging = classify(iss.Name())
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].NotAfter.Before(out[j].NotAfter) })
	return out, nil
}

func parse(path string) (Cert, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Cert{}, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return Cert{}, os.ErrInvalid
	}
	x, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return Cert{}, err
	}
	domains := append([]string{}, x.DNSNames...)
	for _, ip := range x.IPAddresses {
		domains = append(domains, ip.String())
	}
	if len(domains) == 0 && x.Subject.CommonName != "" {
		domains = []string{x.Subject.CommonName}
	}
	return Cert{
		Domains:   domains,
		Issuer:    x.Issuer.CommonName,
		NotBefore: x.NotBefore,
		NotAfter:  x.NotAfter,
		DaysLeft:  int(time.Until(x.NotAfter).Hours() / 24),
		HoursLeft: int(time.Until(x.NotAfter).Hours()),
		Serial:    x.SerialNumber.Text(16),
		KeyType:   x.PublicKeyAlgorithm.String(),
	}, nil
}

func classify(issuerKey string) (source string, staging bool) {
	k := strings.ToLower(issuerKey)
	staging = strings.Contains(k, "staging")
	switch {
	case strings.Contains(k, "letsencrypt"):
		return "letsencrypt", staging
	case strings.Contains(k, "zerossl"):
		return "zerossl", staging
	case k == "local" || strings.HasPrefix(k, "local"):
		return "internal", false
	default:
		return "other", staging
	}
}

// RootCA returns caddy's internal root certificate (for `tls internal`), the
// file an operator imports into browsers to trust LAN sites.
func RootCA(storage string) ([]byte, error) {
	return os.ReadFile(filepath.Join(storage, "pki", "authorities", "local", "root.crt"))
}
