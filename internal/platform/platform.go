// Package platform describes the host caddyforge runs on. Everything here is
// read-only probing; install steps consult it and never write.
package platform

import (
	"bufio"
	"context"
	"os"
	"os/user"
	"strconv"
	"strings"
)

// Init is the process supervisor available to us.
type Init int

const (
	InitUnknown Init = iota
	InitSystemd
	InitNone
)

func (i Init) String() string {
	switch i {
	case InitSystemd:
		return "systemd"
	case InitNone:
		return "none"
	default:
		return "unknown"
	}
}

// Info is a snapshot of the host.
type Info struct {
	GOOS      string
	GOARCH    string
	Distro    string // e.g. "debian", "ubuntu"
	DistroVer string // e.g. "12", "24.04"
	Init      Init
	Virt      string // "lxc", "lxc-unprivileged", "docker", "kvm", "" if bare/unknown
	IsRoot    bool
	UID       int
	User      string
	CanBind   bool // ports below 1024 usable by the current user
	Hostname  string
}

// Detect probes the host. Missing files are treated as "unknown" rather than
// errors, so the same binary answers sensibly on Windows, WSL and a real LXC.
func Detect(ctx context.Context) Info {
	info := Info{GOOS: goos(), GOARCH: goarch()}
	info.Distro, info.DistroVer = osRelease()
	info.Init = detectInit()
	info.Virt = detectVirt(ctx)
	info.UID = os.Geteuid()
	info.IsRoot = info.UID == 0
	info.CanBind = info.IsRoot || unprivilegedPortStart() > 80
	if u, err := user.Current(); err == nil {
		info.User = u.Username
	}
	if h, err := os.Hostname(); err == nil {
		info.Hostname = h
	}
	return info
}

// UnprivilegedLXC reports the common Proxmox case: LXC with systemd, no root
// ports unless CAP_NET_BIND_SERVICE is granted to the binaries.
func (i Info) UnprivilegedLXC() bool {
	return strings.HasPrefix(i.Virt, "lxc") && i.Init == InitSystemd && !i.IsRoot
}

func goos() string   { return runtimeGOOS }
func goarch() string { return runtimeGOARCH }

func osRelease() (name, version string) {
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return "unknown", ""
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := cutPair(sc.Text())
		if !ok {
			continue
		}
		switch k {
		case "ID":
			name = v
		case "VERSION_ID":
			version = v
		}
	}
	if name == "" {
		name = "unknown"
	}
	return name, version
}

// cutPair splits KEY="value" and strips quotes.
func cutPair(line string) (string, string, bool) {
	i := strings.IndexByte(line, '=')
	if i < 0 || strings.HasPrefix(line, "#") {
		return "", "", false
	}
	k := line[:i]
	v := strings.Trim(line[i+1:], "\"'")
	return k, v, true
}

func detectInit() Init {
	if _, err := os.Stat("/run/systemd/system"); err == nil {
		return InitSystemd
	}
	if _, err := os.Stat("/sbin/init"); err == nil {
		return InitUnknown
	}
	return InitNone
}

func detectVirt(ctx context.Context) string {
	if out, err := probe(ctx, "systemd-detect-virt"); err == nil && out != "" {
		return out
	}
	// Fallback for containers without systemd available.
	data, err := os.ReadFile("/proc/1/cgroup")
	if err == nil && strings.Contains(string(data), "lxc") {
		return "lxc"
	}
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return "docker"
	}
	return ""
}

// unprivilegedPortStart reads the namespaced sysctl that allows unprivileged
// binds; a missing file (Windows, macOS) means the kernel default of 1024.
func unprivilegedPortStart() int {
	data, err := os.ReadFile("/proc/sys/net/ipv4/ip_unprivileged_port_start")
	if err != nil {
		return 1024
	}
	n, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		return 1024
	}
	return n
}
