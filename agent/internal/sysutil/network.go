package sysutil

import (
	"net"
)

// PrimaryIP detects the primary outbound IP address.
func PrimaryIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:53")
	if err != nil {
		return "127.0.0.1"
	}
	defer conn.Close()

	addr := conn.LocalAddr().(*net.UDPAddr)
	return addr.IP.String()
}
