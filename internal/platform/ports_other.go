//go:build !unix

package platform

import (
	"context"
	"net"
	"strconv"
)

// PortState is what we learned about one TCP port.
type PortState struct {
	Port     int
	Free     bool
	UsedBy   string
	Own      bool
	Listener bool
}

// CheckPorts only probes bindability here; owner resolution is Linux-only.
func CheckPorts(_ context.Context, ports ...int) []PortState {
	states := make([]PortState, 0, len(ports))
	for _, p := range ports {
		st := PortState{Port: p, Free: true}
		ln, err := net.Listen("tcp", net.JoinHostPort("", strconv.Itoa(p)))
		if err != nil {
			st.Free = false
			st.Listener = true
		} else {
			ln.Close()
		}
		states = append(states, st)
	}
	return states
}
