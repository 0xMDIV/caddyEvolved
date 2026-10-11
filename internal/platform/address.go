package platform

import "net"

// PrimaryIP is the address other machines in the LAN most likely reach this
// host on: the source address of the default route. Dialing UDP sends no
// packet, it only asks the kernel which interface it would use. Without a
// default route it falls back to the first private IPv4 of any interface.
func PrimaryIP() string {
	if c, err := net.Dial("udp", "192.0.2.1:9"); err == nil {
		defer c.Close()
		if a, ok := c.LocalAddr().(*net.UDPAddr); ok && !a.IP.IsLoopback() && !a.IP.IsUnspecified() {
			return a.IP.String()
		}
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	var fallback string
	for _, a := range addrs {
		n, ok := a.(*net.IPNet)
		if !ok || n.IP.IsLoopback() || n.IP.IsLinkLocalUnicast() {
			continue
		}
		if v4 := n.IP.To4(); v4 != nil {
			if v4.IsPrivate() {
				return v4.String()
			}
			if fallback == "" {
				fallback = v4.String()
			}
		}
	}
	return fallback
}
