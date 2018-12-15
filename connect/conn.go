package connect

import (
	"fmt"
	"github.com/gotoolkits/libnetgo/netstat"
	"net"
)

func GetLocalToConns() map[string]netstat.Process {
	m := map[string]netstat.Process{}

	netTcpv4List := netstat.Tcp()
	for _, p := range netTcpv4List {
		if p.State == "ESTABLISHED" {
			itemId := fmt.Sprintf("%s:%v-%s:%v", p.Ip, p.Port, p.ForeignIp, p.ForeignPort)
			m[itemId] = p
		}
	}

	netTcpv6List := netstat.Tcp6()
	for _, p := range netTcpv6List {
		if p.State == "ESTABLISHED" {
			// ipaddr := parseIP(p.Ip)
			// port := fmt.Sprintf("%v", p.Port)
			// if !isLoopback(ipaddr) && !isPublicIP(ipaddr) && !isListenPort(port) {
			// 	m[p.Ip] = p.ForeignIp
			// }
			itemId := fmt.Sprintf("%s:%v-%s:%v", p.Ip, p.Port, p.ForeignIp, p.ForeignPort)

			m[itemId] = p

		}
	}

	return m
}

func GetRemoteFromConns() map[string]string {
	m := map[string]string{}

	netTcpv4List := netstat.Tcp()
	for _, p := range netTcpv4List {
		if p.State == "ESTABLISHED" {
			ipaddr := parseIP(p.Ip)
			port := fmt.Sprintf("%v", p.Port)
			if !isLoopback(ipaddr) && isListenPort(port) {
				m[p.ForeignIp] = port
			}
		}
	}

	netTcpv6List := netstat.Tcp6()
	for _, p := range netTcpv6List {
		if p.State == "ESTABLISHED" {
			ipaddr := parseIP(p.Ip)
			port := fmt.Sprintf("%v", p.Port)
			if !isLoopback(ipaddr) && isListenPort(port) {
				m[p.ForeignIp] = port
			}
		}
	}

	return m
}

func isListenPort(port string) bool {
	list := GetListenPortAndNames()
	_, ok := list[port]
	if ok {
		return true
	}
	return false
}

func parseCIDR(str string) (net.IP, *net.IPNet, error) {
	return net.ParseCIDR(str)
}

func parseIP(str string) net.IP {
	return net.ParseIP(str)
}

func isLoopback(ip net.IP) bool {
	return ip.IsLoopback()
}

func isPublicIP(IP net.IP) bool {
	if IP.IsLoopback() || IP.IsLinkLocalMulticast() || IP.IsLinkLocalUnicast() {
		return false
	}
	if ip4 := IP.To4(); ip4 != nil {
		switch true {
		case ip4[0] == 10:
			return false
		case ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31:
			return false
		case ip4[0] == 192 && ip4[1] == 168:
			return false
		default:
			return true
		}
	}
	return false
}
