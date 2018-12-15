package packet

import (
	"errors"
	"fmt"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"log"
	"net"
	"time"
)

type NetPkt struct {
	LocalIP    net.IP
	RemoteIP   net.IP
	LocalPort  layers.TCPPort
	RemotePort layers.TCPPort
	Direct     string
	Len        uint16
}

var (
	snapshot_len int32 = 1024
	promiscuous  bool  = false
	err          error
	timeout      time.Duration = 30 * time.Second
	handle       *pcap.Handle

	ethLayer layers.Ethernet
	ipLayer  layers.IPv4
	tcpLayer layers.TCP

	LocalIP, RemoteIP     net.IP
	LocalPort, RemotePort layers.TCPPort
	Dir                   string
	pLen                  uint16

	PkgAcc map[string]map[string]int64
)

func StartNetSniff(ipAddr string) {

	handle, err := getPcapHandle(ipAddr)
	if err != nil {
		return
	}
	defer handle.Close()

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	PkgAcc = make(map[string]map[string]int64)

	go accumulator()

	for packet := range packetSource.Packets() {
		parser := gopacket.NewDecodingLayerParser(
			layers.LayerTypeEthernet,
			&ethLayer,
			&ipLayer,
			&tcpLayer,
		)
		foundLayerTypes := []gopacket.LayerType{}

		err := parser.DecodeLayers(packet.Data(), &foundLayerTypes)
		if err != nil {
			//	fmt.Println("Trouble decoding layers: ", err)
		}

		for _, layerType := range foundLayerTypes {
			if layerType == layers.LayerTypeIPv4 {

				if ipLayer.SrcIP.String() != ipAddr {
					LocalIP = ipLayer.DstIP
					RemoteIP = ipLayer.SrcIP
					LocalPort = tcpLayer.DstPort
					RemotePort = tcpLayer.SrcPort
					pLen = ipLayer.Length

					Dir = "in"

					itemId := fmt.Sprintf("%s:%d-%s:%d", LocalIP, LocalPort, RemoteIP, RemotePort)

					if _, ok := PkgAcc[itemId]; !ok {
						PkgAcc[itemId] = map[string]int64{
							"in":          0,
							"out":         0,
							"inRate":      0,
							"outRate":     0,
							"lastAccTime": 0,
							"lastAccIn":   0,
							"lastAccOut":  0,
						}
					}

					PkgAcc[itemId][Dir] = PkgAcc[itemId][Dir] + int64(pLen)

				} else {
					LocalIP = ipLayer.SrcIP
					RemoteIP = ipLayer.DstIP
					LocalPort = tcpLayer.SrcPort
					RemotePort = tcpLayer.DstPort
					pLen = ipLayer.Length

					Dir = "out"

					itemId := fmt.Sprintf("%s:%d-%s:%d", LocalIP, LocalPort, RemoteIP, RemotePort)

					if _, ok := PkgAcc[itemId]; !ok {
						PkgAcc[itemId] = map[string]int64{
							"in":          0,
							"out":         0,
							"inRate":      0,
							"outRate":     0,
							"lastAccTime": 0,
							"lastAccIn":   0,
							"lastAccOut":  0,
						}
					}
					PkgAcc[itemId][Dir] = PkgAcc[itemId][Dir] + int64(pLen)
				}
				//	fmt.Println(PkgAcc)
			}
		}
	}
}

func getPcapHandle(ip string) (*pcap.Handle, error) {
	devs, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}
	var device string
	for _, dev := range devs {
		for _, v := range dev.Addresses {
			if v.IP.String() == ip {
				device = dev.Name
				break
			}
		}
	}
	if device == "" {
		return nil, errors.New("find device error")
	}
	fmt.Println(device)
	h, err := pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		return nil, err
	}
	log.Println("Start netconn...")
	var filter string = "tcp and (not broadcast and not multicast)"
	err = h.SetBPFFilter(filter)
	if err != nil {
		return nil, err
	}
	return h, nil
}

func accumulator() {
	for {
		for _, pkgMap := range PkgAcc {
			start := time.Now().Unix()
			in := pkgMap["in"]
			out := pkgMap["out"]

			if pkgMap["lastAccTime"] == 0 {
				pkgMap["lastAccTime"] = start - 3
			}

			last := pkgMap["lastAccTime"]
			pkgMap["lastAccTime"] = start

			durSec := start - last

			if in == 0 {
				pkgMap["inRate"] = 0
			} else {
				pkgMap["inRate"] = (in - pkgMap["lastAccIn"]) / durSec
			}

			if out == 0 {
				pkgMap["outRate"] = 0
			} else {
				pkgMap["outRate"] = (out - pkgMap["lastAccOut"]) / durSec

			}
			//fmt.Println("==>", itemId, " in:", in, " out:", out, " lastAccIn:", pkgMap["lastAccIn"], " lastAccOut:", pkgMap["lastAccOut"], " inRate:", pkgMap["inRate"], " outRate:", pkgMap["outRate"])
			pkgMap["lastAccIn"] = in
			pkgMap["lastAccOut"] = out
		}

		time.Sleep(3 * time.Second)
	}
}
