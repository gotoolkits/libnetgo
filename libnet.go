package main

import (
	"fmt"
	"github.com/gotoolkits/libnetgo/connect"
	"github.com/gotoolkits/libnetgo/packet"
	"time"
)

func main() {

	//fmt.Println(connect.GetListenPortAndNames())
	// fmt.Println(connect.GetLocalToConns())
	// fmt.Println(connect.GetRemoteFromConns())
	go packet.StartNetSniff("172.28.21.69")

	for {
		fmt.Println(connect.GetLocalToConns())
		time.Sleep(2 * time.Second)
	}

}
