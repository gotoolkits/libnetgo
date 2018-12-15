package connect

import (
	"fmt"
	"github.com/gotoolkits/libnetgo/netstat"
)

func GetListenPortAndNames() map[string]string {
	m := map[string]string{}

	netTcpv4List := netstat.Tcp()
	for _, p := range netTcpv4List {
		if p.State == "LISTEN" {
			ipaddr := parseIP(p.Ip)
			if !isLoopback(ipaddr) {
				port := fmt.Sprintf("%v", p.Port)
				m[port] = p.Name
			}
		}
	}

	netTcpv6List := netstat.Tcp6()
	for _, p := range netTcpv6List {
		if p.State == "LISTEN" {
			port := fmt.Sprintf("%v", p.Port)
			m[port] = p.Name
		}
	}

	return m
}
