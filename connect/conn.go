package connect

import (
	"fmt"
	"github.com/gotoolkits/libnetgo/common"
	"github.com/gotoolkits/libnetgo/netstat"
)

func GetConns(connType string) map[string]netstat.Process {
	if connType == "all" {
		return getAllConns()
	} else if connType == "local" {
		return getLocalConns()
	} else {
		return getRemoteConns()
	}
}

func getAllConns() map[string]netstat.Process {
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
			itemId := fmt.Sprintf("%s:%v-%s:%v", p.Ip, p.Port, p.ForeignIp, p.ForeignPort)
			m[itemId] = p
		}
	}
	return m
}

func getLocalConns() map[string]netstat.Process {
	m := map[string]netstat.Process{}

	netTcpv4List := netstat.Tcp()
	for _, p := range netTcpv4List {
		if p.State == "ESTABLISHED" {
			ipaddr := common.ParseIP(p.ForeignIp)
			if !common.IsPublicIP(ipaddr) {
				itemId := fmt.Sprintf("%s:%v-%s:%v", p.Ip, p.Port, p.ForeignIp, p.ForeignPort)
				m[itemId] = p
			}
		}
	}

	netTcpv6List := netstat.Tcp6()
	for _, p := range netTcpv6List {
		if p.State == "ESTABLISHED" {
			ipaddr := common.ParseIP(p.ForeignIp)
			if !common.IsPublicIP(ipaddr) {
				itemId := fmt.Sprintf("%s:%v-%s:%v", p.Ip, p.Port, p.ForeignIp, p.ForeignPort)
				m[itemId] = p
			}

		}
	}
	return m
}

func getRemoteConns() map[string]netstat.Process {
	m := map[string]netstat.Process{}

	netTcpv4List := netstat.Tcp()
	for _, p := range netTcpv4List {
		if p.State == "ESTABLISHED" {
			ipaddr := common.ParseIP(p.ForeignIp)
			if common.IsPublicIP(ipaddr) {
				itemId := fmt.Sprintf("%s:%v-%s:%v", p.Ip, p.Port, p.ForeignIp, p.ForeignPort)
				m[itemId] = p
			}
		}
	}

	netTcpv6List := netstat.Tcp6()
	for _, p := range netTcpv6List {
		if p.State == "ESTABLISHED" {
			ipaddr := common.ParseIP(p.ForeignIp)
			if !common.IsPublicIP(ipaddr) {
				itemId := fmt.Sprintf("%s:%v-%s:%v", p.Ip, p.Port, p.ForeignIp, p.ForeignPort)
				m[itemId] = p
			}
		}
	}
	return m
}

func GetListenPortAndNames() map[string]string {
	m := map[string]string{}

	netTcpv4List := netstat.Tcp()
	for _, p := range netTcpv4List {
		if p.State == "LISTEN" {
			ipaddr := common.ParseIP(p.Ip)
			if !common.IsLoopback(ipaddr) {
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

func isListenPort(port string) bool {
	list := GetListenPortAndNames()
	_, ok := list[port]
	if ok {
		return true
	}
	return false
}
