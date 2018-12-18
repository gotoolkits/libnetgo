package main

import (
	"flag"
	"fmt"
	"github.com/gotoolkits/libnetgo/api"
	"github.com/gotoolkits/libnetgo/common"
	"github.com/gotoolkits/libnetgo/connect"
	"github.com/gotoolkits/libnetgo/netstat"
	log "github.com/sirupsen/logrus"
	"os"
	"time"
)

var (
	h        bool
	svr      bool
	console  bool
	host     string
	interval int
	connType string
)

func init() {
	flag.BoolVar(&h, "h", false, "libnetgo help")
	flag.BoolVar(&svr, "s", true, "api server")
	flag.BoolVar(&console, "c", false, "console mode")
	flag.StringVar(&host, "ip", "", "ip address for pcap.")
	flag.IntVar(&interval, "r", 3, "To get datas interval,default 3 second.")
	flag.StringVar(&connType, "t", "all", "all/remote/local")
	flag.Usage = usage
}

func main() {
	flag.Parse()
	if h {
		flag.Usage()
		os.Exit(0)
	}
	if svr {
		go api.ServerRun()
	}

	//api.ServerRun()

	if len(host) > 1 {
		if ok, _ := common.VerifyIP(host); ok {
			api.HostIP = host
		}
	} else {
		log.Warningln("Unspecified IP parameter'-ip', unable to open packet capture function")
	}

	for {
		if console {
			formatNetstat(connect.GetConns(connType))
		} else {
			connect.GetConns(connType)
		}
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

func usage() {
	fmt.Fprintf(os.Stderr, `libnetgo version: libnetgo/1.0
Usage: libnetgo [-hs] [-ip ipAddr] [-r interval] [-t all/remote/local] 

Options:
`)
	flag.PrintDefaults()
}
