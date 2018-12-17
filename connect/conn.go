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
func GetConnsV6(connType string) map[string]netstat.Process {
	if connType == "all" {
		return getAllConnsV6()
	} else if connType == "local" {
		return getLocalConnsV6()
	} else {
		return getRemoteConnsV6()
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
	return m
}

func getAllConnsV6() map[string]netstat.Process {
	m := map[string]netstat.Process{}

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
	return m
}
func getLocalConnsV6() map[string]netstat.Process {
	m := map[string]netstat.Process{}

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
	return m
}
func getRemoteConnsV6() map[string]netstat.Process {
	m := map[string]netstat.Process{}

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
	return m
}
func GetListenPortAndNamesV6() map[string]string {
	m := map[string]string{}
	netTcpv6List := netstat.Tcp6()
	for _, p := range netTcpv6List {
		if p.State == "LISTEN" {
			port := fmt.Sprintf("%v", p.Port)
			m[port] = p.Name
		}
	}
	return m
}

func GetConnsList() []netstat.Process {

	return []netstat.Process{
		{User: "root",
			Name:        "test",
			Pid:         "1010",
			Exe:         "wget",
			State:       "sss",
			Ip:          "8.8.8.8",
			Port:        8080,
			ForeignIp:   "127.0.0.1",
			ForeignPort: 8080,
			In:          1,
			Out:         1,
			InRate:      1,
			OutRate:     1},
	}
	// return netstat.Tcp()
}

func isListenPort(port string) bool {
	list := GetListenPortAndNames()
	_, ok := list[port]
	if ok {
		return true
	}
	return false
}
