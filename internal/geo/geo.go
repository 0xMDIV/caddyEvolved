// Package geo answers "which country and network is this IP" from the DB-IP
// Lite databases caddyEvolved already downloads for the firewall. Everything
// goes through Resolver, so the MMDB reader behind it can be swapped for an
// own implementation later without touching the callers.
package geo

import (
	"net/netip"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang/v2"
)

// cacheMax bounds the lookup cache; it is simply cleared when full.
const cacheMax = 10000

// Resolver opens the databases lazily and reopens them when the path
// changes (DB-IP publishes a new file every month).
type Resolver struct {
	paths func() (country, asn string)

	mu      sync.Mutex
	country db
	asn     db
	cache   map[string]Info
	checked time.Time
}

// Info is what the UI shows next to an IP; empty fields are unknown.
type Info struct {
	Country string
	ASN     uint
	ASNOrg  string
}

type db struct {
	path string
	r    *maxminddb.Reader
}

// New takes a function returning the current database paths; an empty path
// means that database is not there.
func New(paths func() (country, asn string)) *Resolver {
	return &Resolver{paths: paths, cache: map[string]Info{}}
}

// Country returns the ISO 3166 alpha-2 code or "".
func (r *Resolver) Country(ip string) string { return r.Lookup(ip).Country }

// ASN returns the autonomous system number and its organisation.
func (r *Resolver) ASN(ip string) (uint, string) {
	i := r.Lookup(ip)
	return i.ASN, i.ASNOrg
}

// Lookup answers both questions at once; it never fails, unknown stays empty.
func (r *Resolver) Lookup(ip string) Info {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return Info{}
	}
	addr = addr.Unmap()
	r.mu.Lock()
	defer r.mu.Unlock()
	// Finding the newest file globs the directory; once per lookup burst is enough.
	if time.Since(r.checked) > 30*time.Second {
		r.checked = time.Now()
		cp, ap := r.paths()
		c, a := r.country.use(cp), r.asn.use(ap) // both, no short-circuit
		if c || a {
			r.cache = map[string]Info{}
		}
	}
	if i, ok := r.cache[ip]; ok {
		return i
	}
	var info Info
	if r.country.r != nil {
		var rec struct {
			Country struct {
				ISOCode string `maxminddb:"iso_code"`
			} `maxminddb:"country"`
		}
		if r.country.r.Lookup(addr).Decode(&rec) == nil {
			info.Country = rec.Country.ISOCode
		}
	}
	if r.asn.r != nil {
		var rec struct {
			Number uint   `maxminddb:"autonomous_system_number"`
			Org    string `maxminddb:"autonomous_system_organization"`
		}
		if r.asn.r.Lookup(addr).Decode(&rec) == nil {
			info.ASN, info.ASNOrg = rec.Number, rec.Org
		}
	}
	if len(r.cache) >= cacheMax {
		r.cache = map[string]Info{}
	}
	r.cache[ip] = info
	return info
}

// use (re)opens the database when its path changed. A file that cannot be
// read leaves the database closed; the next path change tries again.
func (d *db) use(path string) (changed bool) {
	if path == d.path {
		return false
	}
	if d.r != nil {
		_ = d.r.Close()
		d.r = nil
	}
	d.path = path
	if path == "" {
		return true
	}
	if rd, err := maxminddb.Open(path); err == nil {
		d.r = rd
	}
	return true
}
