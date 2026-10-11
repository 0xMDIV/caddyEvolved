package toolbox

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net"
	"os"
	"sort"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// resolve picks the first address of host, IPv4 preferred.
func resolve(ctx context.Context, host string) (net.IP, error) {
	if ip := net.ParseIP(host); ip != nil {
		return ip, nil
	}
	addrs, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
	if err != nil {
		return nil, fmt.Errorf("%s löst nicht auf: %w", host, err)
	}
	sort.SliceStable(addrs, func(i, j int) bool { return addrs[i].To4() != nil && addrs[j].To4() == nil })
	return addrs[0], nil
}

// echoConn opens an ICMP socket: raw (root) first, unprivileged datagram
// socket second (needs net.ipv4.ping_group_range).
func echoConn(v6 bool) (*icmp.PacketConn, bool, error) {
	network, dgram, addr := "ip4:icmp", "udp4", "0.0.0.0"
	if v6 {
		network, dgram, addr = "ip6:ipv6-icmp", "udp6", "::"
	}
	if c, err := icmp.ListenPacket(network, addr); err == nil {
		return c, false, nil
	}
	c, err := icmp.ListenPacket(dgram, addr)
	if err != nil {
		return nil, false, fmt.Errorf("ICMP nicht möglich (weder root noch ping_group_range): %w", err)
	}
	return c, true, nil
}

var echoSeq struct {
	sync.Mutex
	n int
}

func nextSeq() int {
	echoSeq.Lock()
	defer echoSeq.Unlock()
	echoSeq.n = (echoSeq.n + 1) & 0xffff
	return echoSeq.n
}

// PingReply is one echo answer.
type PingReply struct {
	Seq int     `json:"seq"`
	RTT float64 `json:"rttMs"` // -1 = lost
	TTL int     `json:"ttl,omitempty"`
}

// PingResult summarises a ping run.
type PingResult struct {
	Host     string      `json:"host"`
	Addr     string      `json:"addr"`
	Sent     int         `json:"sent"`
	Received int         `json:"received"`
	Loss     float64     `json:"loss"`
	Min      float64     `json:"minMs"`
	Avg      float64     `json:"avgMs"`
	Max      float64     `json:"maxMs"`
	Replies  []PingReply `json:"replies"`
}

// Ping sends count echo requests one second apart.
func Ping(ctx context.Context, host string, count int, timeout time.Duration) (PingResult, error) {
	res := PingResult{Host: host}
	if count < 1 || count > 20 {
		count = 4
	}
	ip, err := resolve(ctx, host)
	if err != nil {
		return res, err
	}
	res.Addr = ip.String()
	conn, dgram, err := echoConn(ip.To4() == nil)
	if err != nil {
		return res, err
	}
	defer conn.Close()

	var sum float64
	res.Min = math.MaxFloat64
	for i := 0; i < count; i++ {
		if i > 0 {
			select {
			case <-ctx.Done():
				return res, ctx.Err()
			case <-time.After(time.Second):
			}
		}
		rtt, ttl, err := echo(conn, dgram, ip, nextSeq(), 0, timeout)
		res.Sent++
		r := PingReply{Seq: i + 1, RTT: -1}
		if err == nil {
			res.Received++
			r.RTT, r.TTL = rtt, ttl
			sum += rtt
			res.Min = math.Min(res.Min, rtt)
			res.Max = math.Max(res.Max, rtt)
		}
		res.Replies = append(res.Replies, r)
	}
	if res.Received > 0 {
		res.Avg = round2(sum / float64(res.Received))
		res.Min, res.Max = round2(res.Min), round2(res.Max)
	} else {
		res.Min = 0
	}
	res.Loss = round2(100 * float64(res.Sent-res.Received) / float64(res.Sent))
	return res, nil
}

func round2(v float64) float64 { return math.Round(v*100) / 100 }

// errTimeExceeded carries the router that dropped a packet with ttl 0.
type errTimeExceeded struct{ from net.Addr }

func (e errTimeExceeded) Error() string { return "time exceeded from " + e.from.String() }

// echo sends one request (ttl 0 = system default) and waits for the matching
// reply or a time-exceeded message about it.
func echo(conn *icmp.PacketConn, dgram bool, ip net.IP, seq, ttl int, timeout time.Duration) (float64, int, error) {
	v6 := ip.To4() == nil
	id := os.Getpid() & 0xffff
	var typ icmp.Type = ipv4.ICMPTypeEcho
	proto := 1
	if v6 {
		typ, proto = ipv6.ICMPTypeEchoRequest, 58
	}
	msg := icmp.Message{Type: typ, Body: &icmp.Echo{ID: id, Seq: seq, Data: []byte("caddyEvolved-ping")}}
	data, err := msg.Marshal(nil)
	if err != nil {
		return 0, 0, err
	}
	if ttl > 0 {
		if v6 {
			_ = conn.IPv6PacketConn().SetHopLimit(ttl)
		} else {
			_ = conn.IPv4PacketConn().SetTTL(ttl)
		}
	}
	var dst net.Addr = &net.IPAddr{IP: ip}
	if dgram {
		dst = &net.UDPAddr{IP: ip}
	}
	start := time.Now()
	if _, err := conn.WriteTo(data, dst); err != nil {
		return 0, 0, err
	}
	buf := make([]byte, 1500)
	deadline := start.Add(timeout)
	for {
		_ = conn.SetReadDeadline(deadline)
		n, from, err := conn.ReadFrom(buf)
		if err != nil {
			return 0, 0, err
		}
		rtt := float64(time.Since(start).Microseconds()) / 1000
		m, err := icmp.ParseMessage(proto, buf[:n])
		if err != nil {
			continue
		}
		switch body := m.Body.(type) {
		case *icmp.Echo:
			// Datagram sockets rewrite the id; the sequence still matches.
			if (m.Type == ipv4.ICMPTypeEchoReply || m.Type == ipv6.ICMPTypeEchoReply) && body.Seq == seq && (dgram || body.ID == id) {
				return round2(rtt), 0, nil
			}
		case *icmp.TimeExceeded:
			if quotedSeq(body.Data, v6) == seq {
				return round2(rtt), 0, errTimeExceeded{from}
			}
		case *icmp.DstUnreach:
			if quotedSeq(body.Data, v6) == seq {
				return round2(rtt), 0, fmt.Errorf("unerreichbar (gemeldet von %s)", from)
			}
		}
	}
}

// quotedSeq reads the echo sequence from the original packet quoted in an
// ICMP error (IP header + first 8 bytes of our echo request).
func quotedSeq(b []byte, v6 bool) int {
	hl := 40
	if !v6 {
		if len(b) < 1 {
			return -1
		}
		hl = int(b[0]&0x0f) * 4
	}
	if len(b) < hl+8 {
		return -1
	}
	return int(b[hl+6])<<8 | int(b[hl+7])
}

// Hop is one router on the way.
type Hop struct {
	TTL     int       `json:"ttl"`
	Addr    string    `json:"addr,omitempty"`
	Name    string    `json:"name,omitempty"`
	RTTs    []float64 `json:"rttMs"` // -1 = no answer
	Reached bool      `json:"reached"`
}

// Traceroute walks TTL 1..maxHops with three probes each.
func Traceroute(ctx context.Context, host string, maxHops int, timeout time.Duration) (string, []Hop, error) {
	if maxHops < 1 || maxHops > 40 {
		maxHops = 30
	}
	ip, err := resolve(ctx, host)
	if err != nil {
		return "", nil, err
	}
	conn, dgram, err := echoConn(ip.To4() == nil)
	if err != nil {
		return ip.String(), nil, err
	}
	defer conn.Close()
	var hops []Hop
	silent := 0
	for ttl := 1; ttl <= maxHops; ttl++ {
		if ctx.Err() != nil {
			return ip.String(), hops, ctx.Err()
		}
		h := Hop{TTL: ttl}
		for probe := 0; probe < 3; probe++ {
			rtt, _, err := echo(conn, dgram, ip, nextSeq(), ttl, timeout)
			var te errTimeExceeded
			switch {
			case err == nil:
				h.Reached, h.Addr = true, ip.String()
				h.RTTs = append(h.RTTs, rtt)
			case errors.As(err, &te):
				h.Addr = hostOf(te.from)
				h.RTTs = append(h.RTTs, rtt)
			default:
				h.RTTs = append(h.RTTs, -1)
			}
		}
		if h.Addr != "" {
			silent = 0
			if names, err := net.DefaultResolver.LookupAddr(ctx, h.Addr); err == nil && len(names) > 0 {
				h.Name = trimDot(names[0])
			}
		} else {
			silent++
		}
		hops = append(hops, h)
		// Eight silent hops in a row: the rest of the path drops ICMP.
		if h.Reached || silent >= 8 {
			break
		}
	}
	return ip.String(), hops, nil
}

func hostOf(a net.Addr) string {
	switch v := a.(type) {
	case *net.IPAddr:
		return v.IP.String()
	case *net.UDPAddr:
		return v.IP.String()
	}
	h, _, err := net.SplitHostPort(a.String())
	if err != nil {
		return a.String()
	}
	return h
}

func trimDot(s string) string {
	if len(s) > 0 && s[len(s)-1] == '.' {
		return s[:len(s)-1]
	}
	return s
}
