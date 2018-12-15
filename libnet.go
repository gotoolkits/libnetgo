package main

import (
	"fmt"
	"github.com/gotoolkits/libnetgo/connect"
	"github.com/gotoolkits/libnetgo/netstat"
	"github.com/gotoolkits/libnetgo/packet"
	"time"
)

func main() {

	//fmt.Println(connect.GetListenPortAndNames())
	// fmt.Println(connect.GetLocalToConns())
	// fmt.Println(connect.GetRemoteFromConns())
	go packet.StartNetSniff("172.28.21.69")

	for {
		formatNetstat(connect.GetLocalToConns())
		time.Sleep(2 * time.Second)
	}

}

//| pid | user | program |  iplink |  in | out | sent | received |
//172.20.40.3:51850-172.20.40.42:6030:{root Eye-Agent 8398 /usr/local/eye/agent/bin/eye-agent ESTABLISHED 172.20.40.3 51850 172.20.40.42 6030 562 1002 0 0}

func formatNetstat(ns map[string]netstat.Process) {
	fmt.Println("|  PID  |    USER    |     IPLINK     |    IN(k)   |   OUT(k)   |   SENT(k/s) | RECEIVED(k/s) |    PROGRAM     |  ")
	for itemId, info := range ns {

		fmt.Printf("%-6s %-12s %-40s %-10d %-10d %-8d %-8d %s",
			info.Pid, info.User, itemId, info.In, info.Out, info.InRate, info.OutRate, info.Exe)
	}

}
