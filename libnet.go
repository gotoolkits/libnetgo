package main

import (
	"fmt"
	"github.com/gotoolkits/libnetgo/connect"
	"github.com/gotoolkits/libnetgo/netstat"
	"github.com/gotoolkits/libnetgo/packet"
	"time"
)

func main() {

	go packet.StartNetSniff("172.28.21.69")

	for {
		formatNetstat(connect.GetLocalToConns())
		time.Sleep(2 * time.Second)
	}

}

func formatNetstat(ns map[string]netstat.Process) {
	fmt.Println("=======================================================================================================================")
	fmt.Println("| PID | USER |                    IPLINK              |IN|OUT(k)|SENT|RECEIVED(kB/s)|            PROGRAM               |")
	fmt.Println("=======================================================================================================================")
	for itemId, info := range ns {
		fmt.Printf(" %-6s %-8s %-40s %-6d%-6d%-6d%-6d %-s\n",
			info.Pid, info.User, itemId, info.In/1024, info.Out/1024, info.OutRate/1024, info.InRate/1024, info.Exe)
	}

}
