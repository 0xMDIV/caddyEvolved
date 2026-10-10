//go:build unix

package platform

import (
	"context"
	"errors"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"syscall"
)

// PortState is what we learned about one TCP port.
type PortState struct {
	Port     int
	Free     bool
	UsedBy   string // process name, empty when unknown
	Own      bool   // caddyevolved or caddy itself holds it
	Listener bool   // something is listening
}

// CheckPorts reports which of the given ports are free. On Linux the owning
// process is resolved through /proc inodes, because "port taken" alone is
// useless advice in an installer.
func CheckPorts(ctx context.Context, ports ...int) []PortState {
	owners, _ := listeners(ctx)
	states := make([]PortState, 0, len(ports))
	for _, p := range ports {
		st := PortState{Port: p, Free: true}
		ln, err := net.Listen("tcp", net.JoinHostPort("", strconv.Itoa(p)))
		if err != nil {
			var errno syscall.Errno
			inUse := errors.As(err, &errno) && (errno == syscall.EADDRINUSE || errno == syscall.EADDRNOTAVAIL)
			if !inUse && !strings.Contains(err.Error(), "address already in use") {
				// EACCES and friends: not occupied, just not bindable by us.
				st.Free = true
			} else {
				st.Free = false
				st.Listener = true
			}
		} else {
			ln.Close()
		}
		if name, ok := owners[p]; ok {
			st.UsedBy = name
			st.Free = false
			st.Listener = true
			st.Own = name == "caddy" || name == "caddyevolved"
		}
		states = append(states, st)
	}
	return states
}

// procNetLine matches a /proc/net/tcp{,6} table row.
var procNetLine = regexp.MustCompile(`^\s*\d+:\s+([0-9A-F]+):([0-9A-F]+)\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+\S+\s+(\d+)`)

// listeners maps listening TCP ports to the comm of their owning process.
func listeners(ctx context.Context) (map[int]string, error) {
	inodes := map[string]int{}
	for _, file := range []string{"/proc/net/tcp", "/proc/net/tcp6"} {
		data, err := os.ReadFile(file)
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			m := procNetLine.FindStringSubmatch(line)
			if m == nil {
				continue
			}
			port, err := strconv.ParseInt(m[2], 16, 32)
			if err != nil {
				continue
			}
			inodes[m[3]] = int(port)
		}
	}
	out := map[int]string{}
	if len(inodes) == 0 {
		return out, nil
	}
	procs, err := os.ReadDir("/proc")
	if err != nil {
		return out, err
	}
	for _, pro := range procs {
		if !pro.IsDir() || !allDigits(pro.Name()) {
			continue
		}
		comm, err := os.ReadFile("/proc/" + pro.Name() + "/comm")
		if err != nil {
			continue
		}
		fds, err := os.ReadDir("/proc/" + pro.Name() + "/fd")
		if err != nil {
			continue // kernel threads and processes of other users
		}
		for _, fd := range fds {
			link, err := os.Readlink("/proc/" + pro.Name() + "/fd/" + fd.Name())
			if err != nil || !strings.HasPrefix(link, "socket:[") {
				continue
			}
			inode := strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")
			if port, ok := inodes[inode]; ok {
				if _, exists := out[port]; !exists {
					out[port] = strings.TrimSpace(string(comm))
				}
			}
		}
	}
	return out, ctx.Err()
}

func allDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return len(s) > 0
}
