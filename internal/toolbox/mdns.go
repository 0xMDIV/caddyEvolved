package toolbox

import (
	"context"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

// MDNSService is one announced service instance.
type MDNSService struct {
	Instance string   `json:"instance"`
	Type     string   `json:"type"` // e.g. _http._tcp
	Host     string   `json:"host,omitempty"`
	Port     int      `json:"port,omitempty"`
	Addrs    []string `json:"addrs,omitempty"`
	TXT      []string `json:"txt,omitempty"`
	From     string   `json:"from"`
}

var mdnsGroup = &net.UDPAddr{IP: net.IPv4(224, 0, 0, 251), Port: 5353}

// BrowseMDNS asks the local network which services it offers. Queries go out
// from an ordinary port: per RFC 6762 §6.7 responders then answer by unicast
// straight back, so no conflict with an avahi daemon holding port 5353.
func BrowseMDNS(ctx context.Context, wait time.Duration) ([]MDNSService, error) {
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{})
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	services := map[string]*MDNSService{} // by instance name
	types := map[string]bool{}
	hosts := map[string][]string{} // host name → addresses
	asked := map[string]bool{}

	ask := func(name string, t dnsmessage.Type) {
		key := name + "/" + t.String()
		if asked[key] {
			return
		}
		asked[key] = true
		b := dnsmessage.NewBuilder(nil, dnsmessage.Header{})
		b.EnableCompression()
		_ = b.StartQuestions()
		n, err := dnsmessage.NewName(name)
		if err != nil {
			return
		}
		_ = b.Question(dnsmessage.Question{Name: n, Type: t, Class: dnsmessage.ClassINET})
		msg, err := b.Finish()
		if err == nil {
			_, _ = conn.WriteToUDP(msg, mdnsGroup)
		}
	}
	ask("_services._dns-sd._udp.local.", dnsmessage.TypePTR)

	deadline := time.Now().Add(wait)
	buf := make([]byte, 9000)
	for time.Now().Before(deadline) && ctx.Err() == nil {
		_ = conn.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		var p dnsmessage.Parser
		if _, err := p.Start(buf[:n]); err != nil {
			continue
		}
		_ = p.SkipAllQuestions()
		var records []dnsmessage.Resource
		for _, section := range []func() ([]dnsmessage.Resource, error){p.AllAnswers, p.AllAuthorities, p.AllAdditionals} {
			rs, err := section()
			if err != nil {
				break
			}
			records = append(records, rs...)
		}
		for _, r := range records {
			name := r.Header.Name.String()
			switch body := r.Body.(type) {
			case *dnsmessage.PTRResource:
				target := body.PTR.String()
				if name == "_services._dns-sd._udp.local." {
					if !types[target] {
						types[target] = true
						ask(target, dnsmessage.TypePTR)
					}
					continue
				}
				svc := service(services, target, name)
				svc.From = from.IP.String()
				ask(target, dnsmessage.TypeSRV)
				ask(target, dnsmessage.TypeTXT)
			case *dnsmessage.SRVResource:
				svc := service(services, name, "")
				svc.Host, svc.Port = body.Target.String(), int(body.Port)
				svc.From = from.IP.String()
				ask(svc.Host, dnsmessage.TypeA)
			case *dnsmessage.TXTResource:
				svc := service(services, name, "")
				svc.TXT = body.TXT
			case *dnsmessage.AResource:
				hosts[name] = appendUniq(hosts[name], net.IP(body.A[:]).String())
			case *dnsmessage.AAAAResource:
				hosts[name] = appendUniq(hosts[name], net.IP(body.AAAA[:]).String())
			}
		}
	}

	out := make([]MDNSService, 0, len(services))
	for _, s := range services {
		s.Addrs = hosts[s.Host]
		if len(s.Addrs) == 0 && s.From != "" {
			s.Addrs = []string{s.From}
		}
		out = append(out, *s)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Type != out[j].Type {
			return out[i].Type < out[j].Type
		}
		return out[i].Instance < out[j].Instance
	})
	return out, nil
}

// service finds or creates the entry for an instance name like
// "Wohnzimmer._airplay._tcp.local.".
func service(m map[string]*MDNSService, instance, typ string) *MDNSService {
	if s, ok := m[instance]; ok {
		return s
	}
	label, rest := splitInstance(instance)
	if typ == "" {
		typ = rest
	}
	s := &MDNSService{Instance: label, Type: strings.TrimSuffix(strings.TrimSuffix(typ, "."), ".local")}
	m[instance] = s
	return s
}

// splitInstance separates the (possibly dotted, escaped) instance label from
// its service type.
func splitInstance(name string) (string, string) {
	i := strings.Index(name, "._")
	if i < 0 {
		return strings.TrimSuffix(name, "."), ""
	}
	return strings.ReplaceAll(name[:i], `\ `, " "), name[i+1:]
}

func appendUniq(list []string, v string) []string {
	for _, x := range list {
		if x == v {
			return list
		}
	}
	return append(list, v)
}

// DNSRecord is one answer of a lookup.
type DNSRecord struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

// LookupDNS asks the system resolver for the usual record types.
func LookupDNS(ctx context.Context, name string) ([]DNSRecord, error) {
	name = strings.TrimSuffix(strings.TrimSpace(name), ".")
	if name == "" {
		return nil, fmt.Errorf("Name fehlt")
	}
	r := net.DefaultResolver
	var out []DNSRecord
	if ip := net.ParseIP(name); ip != nil {
		names, err := r.LookupAddr(ctx, name)
		for _, n := range names {
			out = append(out, DNSRecord{"PTR", trimDot(n)})
		}
		return out, err
	}
	if ips, err := r.LookupIPAddr(ctx, name); err == nil {
		for _, ip := range ips {
			t := "A"
			if ip.IP.To4() == nil {
				t = "AAAA"
			}
			out = append(out, DNSRecord{t, ip.IP.String()})
		}
	}
	if c, err := r.LookupCNAME(ctx, name); err == nil && trimDot(c) != name {
		out = append(out, DNSRecord{"CNAME", trimDot(c)})
	}
	if mx, err := r.LookupMX(ctx, name); err == nil {
		for _, m := range mx {
			out = append(out, DNSRecord{"MX", fmt.Sprintf("%d %s", m.Pref, trimDot(m.Host))})
		}
	}
	if ns, err := r.LookupNS(ctx, name); err == nil {
		for _, n := range ns {
			out = append(out, DNSRecord{"NS", trimDot(n.Host)})
		}
	}
	if txt, err := r.LookupTXT(ctx, name); err == nil {
		for _, t := range txt {
			out = append(out, DNSRecord{"TXT", t})
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s: keine Einträge gefunden", name)
	}
	return out, nil
}
