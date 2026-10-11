// Package toolbox holds the network tools of the WebUI: CIDR calculator,
// ping, traceroute, port and host scanner, mDNS browser and DNS lookup. All
// of them run on the server, so they show the network as caddy sees it.
package toolbox

import (
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"strings"
)

// CIDRInfo describes a network.
type CIDRInfo struct {
	Input     string `json:"input"`
	Network   string `json:"network"` // canonical prefix
	Version   int    `json:"version"`
	Address   string `json:"address"` // network address
	Broadcast string `json:"broadcast,omitempty"`
	First     string `json:"first"` // first usable host
	Last      string `json:"last"`  // last usable host
	Netmask   string `json:"netmask,omitempty"`
	Wildcard  string `json:"wildcard,omitempty"`
	Bits      int    `json:"bits"`
	Total     string `json:"total"` // addresses in the block (string: IPv6 is huge)
	Usable    string `json:"usable"`
	Private   bool   `json:"private"`
	Contains  string `json:"contains,omitempty"` // the typed address, if one was given
}

// ParseCIDR accepts "10.0.0.0/8", "10.1.2.3/255.255.0.0", "fd00::/64" or a
// bare address (treated as /32 or /128).
func ParseCIDR(s string) (CIDRInfo, error) {
	s = strings.TrimSpace(s)
	info := CIDRInfo{Input: s}
	var addr netip.Addr
	var bits int
	if a, m, ok := strings.Cut(s, "/"); ok {
		var err error
		if addr, err = netip.ParseAddr(a); err != nil {
			return info, fmt.Errorf("%q ist keine IP-Adresse", a)
		}
		if strings.Contains(m, ".") {
			mask := net.ParseIP(m).To4()
			if mask == nil || !addr.Is4() {
				return info, fmt.Errorf("%q ist keine gültige Netzmaske", m)
			}
			ones, size := net.IPMask(mask).Size()
			if size == 0 {
				return info, fmt.Errorf("Netzmaske %s ist nicht zusammenhängend", m)
			}
			bits = ones
		} else if _, err := fmt.Sscanf(m, "%d", &bits); err != nil {
			return info, fmt.Errorf("Präfixlänge %q ungültig", m)
		}
	} else {
		var err error
		if addr, err = netip.ParseAddr(s); err != nil {
			return info, fmt.Errorf("%q ist keine IP-Adresse oder kein Netz", s)
		}
		bits = addr.BitLen()
	}
	addr = addr.Unmap()
	if bits < 0 || bits > addr.BitLen() {
		return info, fmt.Errorf("Präfixlänge %d außerhalb 0–%d", bits, addr.BitLen())
	}
	prefix := netip.PrefixFrom(addr, bits).Masked()
	info.Network = prefix.String()
	info.Bits = bits
	info.Address = prefix.Addr().String()
	info.Private = addr.IsPrivate() || addr.IsLoopback() || addr.IsLinkLocalUnicast()
	if addr != prefix.Addr() {
		info.Contains = addr.String()
	}
	last := lastAddr(prefix)
	total := new(big.Int).Lsh(big.NewInt(1), uint(addr.BitLen()-bits))
	info.Total = total.String()

	if addr.Is4() {
		info.Version = 4
		mask := net.CIDRMask(bits, 32)
		info.Netmask = net.IP(mask).String()
		wild := make(net.IP, 4)
		for i := range mask {
			wild[i] = ^mask[i]
		}
		info.Wildcard = wild.String()
		switch {
		case bits == 32:
			info.First, info.Last, info.Usable = info.Address, info.Address, "1"
		case bits == 31: // RFC 3021 point-to-point: both usable
			info.First, info.Last, info.Usable = info.Address, last.String(), "2"
		default:
			info.Broadcast = last.String()
			info.First = prefix.Addr().Next().String()
			info.Last = last.Prev().String()
			info.Usable = new(big.Int).Sub(total, big.NewInt(2)).String()
		}
	} else {
		info.Version = 6
		info.First, info.Last, info.Usable = info.Address, last.String(), info.Total
	}
	return info, nil
}

func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Addr().AsSlice()
	host := len(b)*8 - p.Bits()
	for i := len(b) - 1; i >= 0 && host > 0; i-- {
		n := min(host, 8)
		b[i] |= byte(1<<n - 1)
		host -= n
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

// RangeToCIDRs splits an address range into the fewest prefixes that cover
// it exactly, e.g. 10.0.0.5–10.0.0.20 → 10.0.0.5/32, 10.0.0.6/31, ….
func RangeToCIDRs(from, to string) ([]string, error) {
	a, err := netip.ParseAddr(strings.TrimSpace(from))
	if err != nil {
		return nil, fmt.Errorf("Start %q ist keine IP-Adresse", from)
	}
	b, err := netip.ParseAddr(strings.TrimSpace(to))
	if err != nil {
		return nil, fmt.Errorf("Ende %q ist keine IP-Adresse", to)
	}
	a, b = a.Unmap(), b.Unmap()
	if a.Is4() != b.Is4() {
		return nil, errors.New("Start und Ende müssen dieselbe IP-Version haben")
	}
	if b.Less(a) {
		a, b = b, a
	}
	var out []string
	for {
		// Largest block that starts at a and does not pass b.
		bits := a.BitLen()
		for bits > 0 {
			p := netip.PrefixFrom(a, bits-1)
			if p.Masked().Addr() != a || lastAddr(p.Masked()).Compare(b) > 0 {
				break
			}
			bits--
		}
		p := netip.PrefixFrom(a, bits)
		out = append(out, p.String())
		if len(out) > 512 {
			return nil, errors.New("Bereich ergibt mehr als 512 Netze – bitte enger fassen")
		}
		end := lastAddr(p)
		if end.Compare(b) >= 0 {
			return out, nil
		}
		a = end.Next()
	}
}
