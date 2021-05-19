package main

import (
	"fmt"
	"log"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func main() {
	// devices, err := pcap.FindAllDevs()
	// if err != nil {
	// 	log.Fatal(err)
	// }

	// for _, device := range devices {
	// 	// fmt.Println(device)
	// 	for _, addr := range device.Addresses {
	// 		fmt.Printf("device: %s: %s\n", device.Name, addr)
	// 		fmt.Println("- Subnet mask: ", addr.Netmask)
	// 	}
	// }

	var (
		device       string = "eth0"
		snapshot_len int32  = 1024
		promiscuous  bool   = false
		err          error
		timeout      time.Duration = 5 * time.Second
		handle       *pcap.Handle

		ethLayer layers.Ethernet
		ipLayer  layers.IPv4
		tcpLayer layers.TCP
		udpLayer layers.UDP
		dnsLayer layers.DNS
	)

	handle, err = pcap.OpenLive(device, snapshot_len, promiscuous, timeout)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()
	// Set filter
	var filter string = "udp and port 53"
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("Only capturing UDP port 53 packets.")
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	// for packet := range packetSource.Packets() {
	// 	fmt.Println(packet)
	// 	// Let's see if the packet is TCP
	// 	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	// 	if dnsLayer != nil {
	// 		fmt.Println("DNS layer detected.")
	// 		dns, _ := dnsLayer.(*layers.DNS)
	// 		fmt.Printf("dns data id %d\n", dns.ID)
	// 		for _, v := range dns.Answers {
	// 			fmt.Println("Answers:", v.String())
	// 			fmt.Println("Answers-name:", v.Type)
	// 		}

	// 	}
	// }

	for packet := range packetSource.Packets() {
		fmt.Println(packet)
		parser := gopacket.NewDecodingLayerParser(
			layers.LayerTypeEthernet,
			&ethLayer,
			&ipLayer,
			&tcpLayer,
			&udpLayer,
			&dnsLayer,
		)
		foundLayerTypes := []gopacket.LayerType{}
		err := parser.DecodeLayers(packet.Data(), &foundLayerTypes)
		if err != nil {
			fmt.Println("Trouble decoding layers: ", err)
		}
		for _, layerType := range foundLayerTypes {
			if layerType == layers.LayerTypeIPv4 {
				fmt.Println("IPv4: ", ipLayer.SrcIP, "->", ipLayer.DstIP)
			}
			if layerType == layers.LayerTypeTCP {
				fmt.Println("TCP Port: ", tcpLayer.SrcPort, "->", tcpLayer.DstPort)
				fmt.Println("TCP SYN:", tcpLayer.SYN, " | ACK:", tcpLayer.ACK)
			}
			if layerType == layers.LayerTypeUDP {
				fmt.Println("UDP Port: ", udpLayer.SrcPort, "->", udpLayer.DstPort)
			}
			if layerType == layers.LayerTypeDNS {
				fmt.Println("dns ID: ", dnsLayer.ID)
				for _, answer := range dnsLayer.Answers {
					fmt.Println(answer)
					fmt.Println(string(answer.Name), answer.Type, answer.IP, answer.URI)
				}
			}
		}
	}
}
