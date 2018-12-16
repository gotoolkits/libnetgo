package common

import (
	"log"
	"net"
	"os/exec"
	"regexp"
	"runtime"
	"strings"

	"github.com/axgle/mahonia"
)

// type ClientConfig struct {
// 	Cycle  int    // 信息传输频率，单位：分钟
// 	UDP    bool   // 是否记录UDP请求
// 	LAN    bool   // 是否本地网络请求
// 	Mode   string // 模式，考虑中
// 	Filter struct {
// 		File    []string // 文件hash、文件名
// 		IP      []string // IP地址
// 		Process []string // 进程名、参数
// 	} // 直接过滤不回传的规则
// 	MonitorPath []string // 监控目录列表
// 	Lasttime    string   // 最后一条登录日志时间
// }

// type ComputerInfo struct {
// 	IP       string   // IP地址
// 	System   string   // 操作系统
// 	Hostname string   // 计算机名
// 	Type     string   // 服务器类型
// 	Path     []string // WEB目录
// }

var (
	// Config       ClientConfig
	LocalIP string
	// ServerInfo   ComputerInfo
	ServerIPList []string
)

func Cmdexec(cmd string) string {
	var c *exec.Cmd
	var data string
	system := runtime.GOOS
	argArray := strings.Split(cmd, " ")
	c = exec.Command(argArray[0], argArray[1:]...)
	out, _ := c.CombinedOutput()
	data = string(out)
	if system == "windows" {
		dec := mahonia.NewDecoder("gbk")
		data = dec.ConvertString(data)
	}
	return data
}

func InArray(list []string, value string, regex bool) bool {
	for _, v := range list {
		if regex {
			if ok, err := regexp.Match(v, []byte(value)); ok {
				return true
			} else if err != nil {
				log.Println(err.Error())
			}
		} else {
			if value == v {
				return true
			}
		}
	}
	return false
}

func ParseCIDR(str string) (net.IP, *net.IPNet, error) {
	return net.ParseCIDR(str)
}

func ParseIP(str string) net.IP {
	return net.ParseIP(str)
}

func IsLoopback(ip net.IP) bool {
	return ip.IsLoopback()
}

func IsPublicIP(IP net.IP) bool {
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

func VerifyIP(ipAddr string) (bool, error) {
	ifaces, e := net.Interfaces()
	if e != nil {
		return false, e
	}

	for _, iface := range ifaces {
		addrs, e := iface.Addrs()
		if e != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip == nil || ip.IsLoopback() {
				continue
			}
			ip = ip.To4()
			if ip == nil {
				continue
			}

			if ip.String() == ipAddr {
				return true, nil
			}
		}
	}
	return false, nil
}
