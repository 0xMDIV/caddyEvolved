package toolbox

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// ---- ports -----------------------------------------------------------------

// wellKnown names common ports for the result list.
var wellKnown = map[int]string{
	21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS", 80: "HTTP", 110: "POP3", 111: "RPC", 139: "NetBIOS",
	143: "IMAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "Submission", 631: "IPP", 853: "DNS over TLS", 993: "IMAPS",
	995: "POP3S", 1883: "MQTT", 2049: "NFS", 2019: "Caddy Admin", 3000: "Grafana/Dev", 3306: "MySQL", 3389: "RDP",
	5000: "Synology/Dev", 5001: "Synology HTTPS", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8000: "HTTP-alt",
	8006: "Proxmox VE", 8007: "Proxmox Backup", 8080: "HTTP-alt", 8096: "Jellyfin", 8123: "Home Assistant",
	8443: "HTTPS-alt / UniFi", 8484: "caddyEvolved", 8883: "MQTT TLS", 9000: "Portainer/MinIO", 9090: "Cockpit/Prometheus",
	9100: "Node Exporter", 9443: "Portainer HTTPS", 27017: "MongoDB", 32400: "Plex", 51820: "WireGuard",
}

// CommonPorts is the default port list.
func CommonPorts() []int {
	out := make([]int, 0, len(wellKnown))
	for p := range wellKnown {
		out = append(out, p)
	}
	sort.Ints(out)
	return out
}

// ParsePorts reads "22,80,443,8000-8100"; at most 4096 ports.
func ParsePorts(spec string) ([]int, error) {
	if strings.TrimSpace(spec) == "" {
		return CommonPorts(), nil
	}
	seen := map[int]bool{}
	var out []int
	for _, part := range strings.Split(spec, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		lo, hi, isRange := strings.Cut(part, "-")
		a, err := strconv.Atoi(strings.TrimSpace(lo))
		if err != nil {
			return nil, fmt.Errorf("Port %q ungültig", part)
		}
		b := a
		if isRange {
			if b, err = strconv.Atoi(strings.TrimSpace(hi)); err != nil {
				return nil, fmt.Errorf("Port-Bereich %q ungültig", part)
			}
		}
		if a < 1 || b > 65535 || b < a {
			return nil, fmt.Errorf("Ports müssen zwischen 1 und 65535 liegen (%q)", part)
		}
		for p := a; p <= b; p++ {
			if !seen[p] {
				seen[p] = true
				out = append(out, p)
			}
			if len(out) > 4096 {
				return nil, errors.New("höchstens 4096 Ports pro Scan")
			}
		}
	}
	sort.Ints(out)
	return out, nil
}

// PortResult is one open port.
type PortResult struct {
	Port    int     `json:"port"`
	Service string  `json:"service,omitempty"`
	RTT     float64 `json:"rttMs"`
	Banner  string  `json:"banner,omitempty"`
}

// ScanPorts tries a TCP connect on every port; only open ones are returned.
func ScanPorts(ctx context.Context, host string, ports []int, timeout time.Duration) (string, []PortResult, error) {
	ip, err := resolve(ctx, host)
	if err != nil {
		return "", nil, err
	}
	var mu sync.Mutex
	var open []PortResult
	sem := make(chan struct{}, 200)
	var wg sync.WaitGroup
	for _, p := range ports {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(p int) {
			defer wg.Done()
			defer func() { <-sem }()
			start := time.Now()
			d := net.Dialer{Timeout: timeout}
			c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), strconv.Itoa(p)))
			if err != nil {
				return
			}
			r := PortResult{Port: p, Service: wellKnown[p], RTT: round2(float64(time.Since(start).Microseconds()) / 1000)}
			// Services that speak first (SSH, SMTP, FTP) identify themselves.
			_ = c.SetReadDeadline(time.Now().Add(400 * time.Millisecond))
			buf := make([]byte, 128)
			if n, _ := c.Read(buf); n > 0 {
				r.Banner = strings.TrimSpace(strings.Map(printable, string(buf[:n])))
			}
			c.Close()
			mu.Lock()
			open = append(open, r)
			mu.Unlock()
		}(p)
	}
	wg.Wait()
	sort.Slice(open, func(i, j int) bool { return open[i].Port < open[j].Port })
	return ip.String(), open, ctx.Err()
}

func printable(r rune) rune {
	if r == '\n' || r == '\r' || r == '\t' {
		return ' '
	}
	if r < 32 || r == 127 {
		return -1
	}
	return r
}

// ---- hosts -----------------------------------------------------------------

// HostResult is one live address of a network scan.
type HostResult struct {
	IP     string  `json:"ip"`
	RTT    float64 `json:"rttMs"`
	Via    string  `json:"via"` // icmp | tcp
	Name   string  `json:"name,omitempty"`
	MAC    string  `json:"mac,omitempty"`
	Self   bool    `json:"self,omitempty"`
	OpenOn []int   `json:"openOn,omitempty"`
}

// probePorts answer the TCP fallback for hosts that drop ICMP.
var probePorts = []int{80, 443, 22, 445, 8080, 8006}

// ScanHosts finds live hosts in a network (at most /22, 1024 addresses):
// ICMP echo first, a few TCP ports for hosts that drop ping, then reverse DNS
// and the MAC from the kernel's ARP table.
func ScanHosts(ctx context.Context, cidr string, timeout time.Duration) ([]HostResult, error) {
	info, err := ParseCIDR(cidr)
	if err != nil {
		return nil, err
	}
	if info.Version != 4 {
		return nil, errors.New("Host-Scan nur für IPv4-Netze")
	}
	if info.Bits < 22 {
		return nil, errors.New("Netz zu groß – höchstens /22 (1024 Adressen)")
	}
	prefix := netip.MustParsePrefix(info.Network)
	var targets []netip.Addr
	for a := prefix.Addr(); prefix.Contains(a); a = a.Next() {
		if info.Bits <= 30 && (a == prefix.Addr() || a.String() == info.Broadcast) {
			continue
		}
		targets = append(targets, a)
	}

	found := map[string]*HostResult{}
	var mu sync.Mutex
	mark := func(ip string, rtt float64, via string, port int) {
		mu.Lock()
		defer mu.Unlock()
		h, ok := found[ip]
		if !ok {
			h = &HostResult{IP: ip, RTT: rtt, Via: via}
			found[ip] = h
		}
		if port > 0 {
			h.OpenOn = append(h.OpenOn, port)
		}
	}

	// ICMP: one socket, all requests out, collect replies until the timeout.
	if conn, dgram, err := echoConn(false); err == nil {
		sent := map[string]time.Time{}
		id := os.Getpid() & 0xffff
		done := make(chan struct{})
		go func() {
			defer close(done)
			buf := make([]byte, 1500)
			for {
				_ = conn.SetReadDeadline(time.Now().Add(timeout))
				n, from, err := conn.ReadFrom(buf)
				if err != nil {
					return
				}
				m, err := icmp.ParseMessage(1, buf[:n])
				if err != nil || m.Type != ipv4.ICMPTypeEchoReply {
					continue
				}
				if e, ok := m.Body.(*icmp.Echo); !ok || (!dgram && e.ID != id) {
					continue
				}
				ip := hostOf(from)
				mu.Lock()
				start, ok := sent[ip]
				mu.Unlock()
				if ok {
					mark(ip, round2(float64(time.Since(start).Microseconds())/1000), "icmp", 0)
				}
			}
		}()
		for i, a := range targets {
			msg := icmp.Message{Type: ipv4.ICMPTypeEcho, Body: &icmp.Echo{ID: id, Seq: i & 0xffff, Data: []byte("caddyEvolved-scan")}}
			data, _ := msg.Marshal(nil)
			var dst net.Addr = &net.IPAddr{IP: a.AsSlice()}
			if dgram {
				dst = &net.UDPAddr{IP: a.AsSlice()}
			}
			mu.Lock()
			sent[a.String()] = time.Now()
			mu.Unlock()
			_, _ = conn.WriteTo(data, dst)
			if i%64 == 63 {
				time.Sleep(5 * time.Millisecond) // do not flood small routers
			}
		}
		<-done
		conn.Close()
	}

	// TCP fallback for everything that stayed quiet.
	sem := make(chan struct{}, 256)
	var wg sync.WaitGroup
	for _, a := range targets {
		mu.Lock()
		_, ok := found[a.String()]
		mu.Unlock()
		if ok || ctx.Err() != nil {
			continue
		}
		for _, p := range probePorts {
			wg.Add(1)
			sem <- struct{}{}
			go func(ip string, p int) {
				defer wg.Done()
				defer func() { <-sem }()
				start := time.Now()
				d := net.Dialer{Timeout: timeout}
				c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(p)))
				if err != nil {
					// "connection refused" also proves the host is up.
					if strings.Contains(err.Error(), "refused") {
						mark(ip, round2(float64(time.Since(start).Microseconds())/1000), "tcp", 0)
					}
					return
				}
				c.Close()
				mark(ip, round2(float64(time.Since(start).Microseconds())/1000), "tcp", p)
			}(a.String(), p)
		}
	}
	wg.Wait()

	self := localAddrs()
	arp := arpTable()
	out := make([]HostResult, 0, len(found))
	var nameWG sync.WaitGroup
	for _, h := range found {
		h.MAC = arp[h.IP]
		h.Self = self[h.IP]
		sort.Ints(h.OpenOn)
		out = append(out, *h)
	}
	for i := range out {
		nameWG.Add(1)
		go func(h *HostResult) {
			defer nameWG.Done()
			c, cancel := context.WithTimeout(ctx, 2*time.Second)
			defer cancel()
			if names, err := net.DefaultResolver.LookupAddr(c, h.IP); err == nil && len(names) > 0 {
				h.Name = trimDot(names[0])
			}
		}(&out[i])
	}
	nameWG.Wait()
	sort.Slice(out, func(i, j int) bool {
		a, _ := netip.ParseAddr(out[i].IP)
		b, _ := netip.ParseAddr(out[j].IP)
		return a.Less(b)
	})
	return out, ctx.Err()
}

// arpTable reads the kernel's neighbour cache (filled by the scan itself).
func arpTable() map[string]string {
	out := map[string]string{}
	fh, err := os.Open("/proc/net/arp")
	if err != nil {
		return out
	}
	defer fh.Close()
	sc := bufio.NewScanner(fh)
	sc.Scan() // header
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) >= 4 && f[3] != "00:00:00:00:00:00" {
			out[f[0]] = f[3]
		}
	}
	return out
}

func localAddrs() map[string]bool {
	out := map[string]bool{}
	addrs, _ := net.InterfaceAddrs()
	for _, a := range addrs {
		if n, ok := a.(*net.IPNet); ok {
			out[n.IP.String()] = true
		}
	}
	return out
}

// LocalNetworks lists the IPv4 networks of this host's interfaces, as scan
// suggestions.
func LocalNetworks() []string {
	var out []string
	ifs, _ := net.Interfaces()
	for _, i := range ifs {
		if i.Flags&net.FlagLoopback != 0 || i.Flags&net.FlagUp == 0 {
			continue
		}
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			n, ok := a.(*net.IPNet)
			if !ok || n.IP.To4() == nil {
				continue
			}
			ones, _ := n.Mask.Size()
			if ones < 22 {
				ones = 24 // suggest the host's /24 inside a bigger network
			}
			p := netip.PrefixFrom(netip.MustParseAddr(n.IP.String()), ones).Masked()
			out = append(out, p.String())
		}
	}
	return out
}
