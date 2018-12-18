/*
   Simple Netstat implementation by golang.
   Get linux system net data from:
      /proc/net/tcp
      /proc/net/udp
   Parse net system pid info from:
      /proc/[0-9]/fd/[0-9].
*/

package netstat

import (
	"fmt"
	"github.com/gotoolkits/libnetgo/packet"
	"github.com/gotoolkits/libnetgo/user"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

const (
	PROC_TCP  = "/proc/net/tcp"
	PROC_UDP  = "/proc/net/udp"
	PROC_TCP6 = "/proc/net/tcp6"
	PROC_UDP6 = "/proc/net/udp6"
)

var STATE = map[string]string{
	"01": "ESTABLISHED",
	"02": "SYN_SENT",
	"03": "SYN_RECV",
	"04": "FIN_WAIT1",
	"05": "FIN_WAIT2",
	"06": "TIME_WAIT",
	"07": "CLOSE",
	"08": "CLOSE_WAIT",
	"09": "LAST_ACK",
	"0A": "LISTEN",
	"0B": "CLOSING",
}

type Process struct {
	User        string `json:"user"`
	Name        string `json:"name"`
	Pid         string `json:"pid"`
	Exe         string `json:"exe"`
	State       string `json:"state"`
	Ip          string `json:"ip"`
	Port        int64  `json:"port"`
	ForeignIp   string `json:"foreignip"`
	ForeignPort int64  `json:"foreignport"`
	In          int64  `json:"in"`
	Out         int64  `json:"out"`
	InRate      int64  `json:"inRate"`
	OutRate     int64  `json:"outRate"`
}

func getData(t string) []string {
	var proc_t string

	if t == "tcp" {
		proc_t = PROC_TCP
	} else if t == "udp" {
		proc_t = PROC_UDP
	} else if t == "tcp6" {
		proc_t = PROC_TCP6
	} else if t == "udp6" {
		proc_t = PROC_UDP6
	} else {
		fmt.Printf("%s is a invalid type, tcp and udp only!\n", t)
		os.Exit(1)
	}

	data, err := ioutil.ReadFile(proc_t)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	lines := strings.Split(string(data), "\n")

	// Return lines without Header line and blank line on the end
	return lines[1 : len(lines)-1]

}

func hexToDec(h string) int64 {
	// convert hexadecimal to decimal.
	d, err := strconv.ParseInt(h, 16, 32)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	return d
}

func convertIp(ip string) string {
	// Convert the ipv4 to decimal. Have to rearrange the ip because the
	// default value is in little Endian order.

	var out string

	// Check ip size if greater than 8 is a ipv6 type
	if len(ip) > 8 {
		i := []string{ip[30:32],
			ip[28:30],
			ip[26:28],
			ip[24:26],
			ip[22:24],
			ip[20:22],
			ip[18:20],
			ip[16:18],
			ip[14:16],
			ip[12:14],
			ip[10:12],
			ip[8:10],
			ip[6:8],
			ip[4:6],
			ip[2:4],
			ip[0:2]}
		out = fmt.Sprintf("%v%v:%v%v:%v%v:%v%v:%v%v:%v%v:%v%v:%v%v",
			i[14], i[15], i[13], i[12],
			i[10], i[11], i[8], i[9],
			i[6], i[7], i[4], i[5],
			i[2], i[3], i[0], i[1])

	} else {
		i := []int64{hexToDec(ip[6:8]),
			hexToDec(ip[4:6]),
			hexToDec(ip[2:4]),
			hexToDec(ip[0:2])}

		out = fmt.Sprintf("%v.%v.%v.%v", i[0], i[1], i[2], i[3])
	}
	return out
}

func findPid(inode string) string {
	// Loop through all fd dirs of process on /proc to compare the inode and
	// get the pid.

	pid := "-"

	d, err := filepath.Glob("/proc/[0-9]*/fd/[0-9]*")
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	re := regexp.MustCompile(inode)
	for _, item := range d {
		path, _ := os.Readlink(item)
		out := re.FindString(path)
		if len(out) != 0 {
			pid = strings.Split(item, "/")[2]
		}
	}
	return pid
}

func getProcessExe(pid string) string {
	exe := fmt.Sprintf("/proc/%s/exe", pid)
	path, _ := os.Readlink(exe)
	return path
}

func getProcessName(exe string) string {
	n := strings.Split(exe, "/")
	name := n[len(n)-1]
	return strings.Title(name)
}

func getUser(uid string) string {
	// rewrite package os/user funcation LookupId dependence on cgo
	u, err := user.LookupUserId(uid)
	if err != nil {
		fmt.Println(err)
	}

	return u.Username
}

func removeEmpty(array []string) []string {
	// remove empty data from line
	var new_array []string
	for _, i := range array {
		if i != "" {
			new_array = append(new_array, i)
		}
	}
	return new_array
}

// Return a array of Process with Name, Ip, Port, State .. etc
// Require Root acess to get information about some processes.
func netstat(t string) []Process {

	var Processes []Process
	var in, out, inRate, outRate int64

	data := getData(t)

	for _, line := range data {

		// local ip and port
		line_array := removeEmpty(strings.Split(strings.TrimSpace(line), " "))

		ip_port := strings.Split(line_array[1], ":")
		ip := convertIp(ip_port[0])
		port := hexToDec(ip_port[1])

		// foreign ip and port
		fip_port := strings.Split(line_array[2], ":")

		fip := convertIp(fip_port[0])

		// not write local listenning records
		if fip == "0.0.0.0" {
			continue
		}

		fport := hexToDec(fip_port[1])

		state := STATE[line_array[3]]
		uid := getUser(line_array[7])
		pid := findPid(line_array[9])
		exe := getProcessExe(pid)
		name := getProcessName(exe)

		// itemid index pcap Map
		itemId := fmt.Sprintf("%s:%v-%s:%v", ip, port, fip, fport)
		if v, ok := packet.PkgAcc[itemId]; ok {
			in = v["in"]
			inRate = v["inRate"]
			out = v["out"]
			outRate = v["outRate"]
		}

		p := Process{uid, name, pid, exe, state, ip, port, fip, fport, in, out, inRate, outRate}

		Processes = append(Processes, p)

	}

	return Processes
}

// Tcp func Get a slice of Process type with TCP data
func Tcp() []Process {
	data := netstat("tcp")
	return data
}

// Udp func Get a slice of Process type with UDP data
func Udp() []Process {
	data := netstat("udp")
	return data
}

// Tcp6 func Get a slice of Process type with TCP6 data
func Tcp6() []Process {
	data := netstat("tcp6")
	return data
}

// Udp6 func Get a slice of Process type with UDP6 data
func Udp6() []Process {
	data := netstat("udp6")
	return data
}
