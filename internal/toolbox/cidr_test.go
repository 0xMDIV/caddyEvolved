package toolbox

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"
)

func TestParseCIDR(t *testing.T) {
	cases := []struct {
		in                                        string
		network, first, last, bcast, mask, usable string
	}{
		{"192.168.10.27/24", "192.168.10.0/24", "192.168.10.1", "192.168.10.254", "192.168.10.255", "255.255.255.0", "254"},
		{"10.1.2.3/255.255.0.0", "10.1.0.0/16", "10.1.0.1", "10.1.255.254", "10.1.255.255", "255.255.0.0", "65534"},
		{"172.16.5.4/31", "172.16.5.4/31", "172.16.5.4", "172.16.5.5", "", "255.255.255.254", "2"},
		{"8.8.8.8", "8.8.8.8/32", "8.8.8.8", "8.8.8.8", "", "255.255.255.255", "1"},
		{"fd00:1::5/64", "fd00:1::/64", "fd00:1::", "fd00:1::ffff:ffff:ffff:ffff", "", "", "18446744073709551616"},
	}
	for _, c := range cases {
		got, err := ParseCIDR(c.in)
		if err != nil {
			t.Fatalf("%s: %v", c.in, err)
		}
		if got.Network != c.network || got.First != c.first || got.Last != c.last || got.Broadcast != c.bcast || got.Netmask != c.mask || got.Usable != c.usable {
			t.Errorf("%s: %+v", c.in, got)
		}
	}
	for _, bad := range []string{"300.1.1.1/24", "10.0.0.0/33", "10.0.0.0/255.0.255.0", "foo"} {
		if _, err := ParseCIDR(bad); err == nil {
			t.Errorf("%s accepted", bad)
		}
	}
}

func TestRangeToCIDRs(t *testing.T) {
	cases := map[[2]string]string{
		{"10.0.0.0", "10.0.0.255"}:       "10.0.0.0/24",
		{"10.0.0.5", "10.0.0.20"}:        "10.0.0.5/32 10.0.0.6/31 10.0.0.8/29 10.0.0.16/30 10.0.0.20/32",
		{"192.168.1.10", "192.168.1.10"}: "192.168.1.10/32",
		{"0.0.0.0", "255.255.255.255"}:   "0.0.0.0/0",
		{"fd00::", "fd00::ff"}:           "fd00::/120",
	}
	for in, want := range cases {
		got, err := RangeToCIDRs(in[0], in[1])
		if err != nil {
			t.Fatalf("%v: %v", in, err)
		}
		if strings.Join(got, " ") != want {
			t.Errorf("%v: %v, want %s", in, got, want)
		}
	}
	if _, err := RangeToCIDRs("10.0.0.1", "fd00::1"); err == nil {
		t.Error("mixed versions accepted")
	}
}

func TestParsePorts(t *testing.T) {
	got, err := ParsePorts("443, 22,8000-8003,22")
	if err != nil || strings.Trim(strings.Join(strings.Fields(strings.Trim(fmt.Sprint(got), "[]")), ","), ",") != "22,443,8000,8001,8002,8003" {
		t.Fatalf("%v %v", got, err)
	}
	for _, bad := range []string{"0", "70000", "10-5", "x", "1-5000"} {
		if _, err := ParsePorts(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
	if def, _ := ParsePorts(""); len(def) < 20 {
		t.Fatal("default list too short")
	}
}

func TestSplitInstance(t *testing.T) {
	l, typ := splitInstance(`Wohnzimmer\ TV._airplay._tcp.local.`)
	if l != "Wohnzimmer TV" || typ != "_airplay._tcp.local." {
		t.Fatalf("%q %q", l, typ)
	}
}

// TestScanPortsLocal opens a listener and finds it.
func TestScanPortsLocal(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Write([]byte("SSH-2.0-test\r\n"))
			c.Close()
		}
	}()
	port := ln.Addr().(*net.TCPAddr).Port
	_, open, err := ScanPorts(context.Background(), "127.0.0.1", []int{port, port + 1}, 500*time.Millisecond)
	if err != nil || len(open) != 1 || open[0].Port != port || open[0].Banner != "SSH-2.0-test" {
		t.Fatalf("%+v %v", open, err)
	}
}

func TestPrintableTXT(t *testing.T) {
	for in, want := range map[string]string{
		"version=1.4":       "version=1.4",
		"xa=\x01\xff":       "xa=0x01ff",
		"flag":              "flag",
		"\x00\x01":          "0x0001",
		"nn=ha-thread-9793": "nn=ha-thread-9793",
		"name=Küche":        "name=Küche",
	} {
		if got := printableTXT(in); got != want {
			t.Errorf("printableTXT(%q) = %q, want %q", in, got, want)
		}
	}
}
