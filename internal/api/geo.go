package api

import (
	"caddyevolved/internal/blocklists"
	"caddyevolved/internal/geo"
)

// ipGeo is what the UI shows next to an IP.
type ipGeo struct {
	Country string `json:"country,omitempty"`
	ASN     uint   `json:"asn,omitempty"`
	ASNOrg  string `json:"asnOrg,omitempty"`
}

// newGeo resolves against the DB-IP databases the firewall downloads.
func (s *Server) newGeo() *geo.Resolver {
	return geo.New(func() (string, string) {
		return blocklists.GeoPath(s.geoDir(), blocklists.GeoCountry), blocklists.GeoPath(s.geoDir(), blocklists.GeoASN)
	})
}

// geoFor looks up each distinct IP once; unknown IPs are left out, so the
// map stays small and the UI simply shows nothing for them.
func (s *Server) geoFor(ips []string) map[string]ipGeo {
	out := map[string]ipGeo{}
	if s.Geo == nil {
		return out
	}
	for _, ip := range ips {
		if _, done := out[ip]; done || ip == "" {
			continue
		}
		if i := s.Geo.Lookup(ip); i != (geo.Info{}) {
			out[ip] = ipGeo{Country: i.Country, ASN: i.ASN, ASNOrg: i.ASNOrg}
		}
	}
	return out
}
