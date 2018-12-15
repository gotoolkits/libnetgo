package main

import (
	"flag"
	"fmt"
	"github.com/gotoolkits/libnetgo/connect"
	"github.com/gotoolkits/libnetgo/netstat"
	"github.com/gotoolkits/libnetgo/packet"
	"os"
	"time"
)

var (
	host     string
	interval int
)

func init() {
	flag.StringVar(&host, "ip", "", "ip address for pcap.")
	flag.IntVar(&interval, "r", 2, "To get datas interval,default 2 second.")
}

func main() {
	flag.Parse()

	if len(host) < 8 {
		fmt.Println("please set ip address for pcap, '-ip x.x.x.x' ")
		os.Exit(1)
	}

	go packet.StartNetSniff(host)

	for {
		formatNetstat(connect.GetLocalToConns())
		time.Sleep(time.Duration(interval) * time.Second)
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
