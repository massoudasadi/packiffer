// +build linux windows darwin freebsd netbsd openbsd

package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

func (p *packiffer) packetInfo(packet *gopacket.Packet) {

	fmt.Println("All packet layers:")
	for _, layer := range (*packet).Layers() {
		fmt.Println("- ", layer.LayerType())
	}

	ethernetLayer := (*packet).Layer(layers.LayerTypeEthernet)
	if ethernetLayer != nil {
		fmt.Println("Ethernet layer detected.")
		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
		fmt.Println("Source MAC: ", ethernetPacket.SrcMAC)
		fmt.Println("Destination MAC: ", ethernetPacket.DstMAC)
		fmt.Println("Ethernet type: ", ethernetPacket.EthernetType)
		fmt.Println()
	}

	arpLayer := (*packet).Layer(layers.LayerTypeARP)
	if arpLayer != nil {
		fmt.Println("Arp layer detected.")
		arp, _ := arpLayer.(*layers.ARP)
		fmt.Printf("AddrType: %d", arp.AddrType)
		fmt.Printf("Protocol: %d", arp.Protocol)
		fmt.Printf("SourceHwAddress: %d", arp.SourceHwAddress)
		fmt.Printf("SourceProtAddress: %d", arp.SourceProtAddress)
		fmt.Printf("DstHwAddress: %d", arp.DstHwAddress)
		fmt.Printf("DstProtAddress: %d", arp.DstProtAddress)
		fmt.Println()
	}

	ipv4Layer := (*packet).Layer(layers.LayerTypeIPv4)
	if ipv4Layer != nil {
		fmt.Println("IPv4 layer detected.")
		ipv4, _ := ipv4Layer.(*layers.IPv4)
		fmt.Printf("From %s to %s", ipv4.SrcIP, ipv4.DstIP)
		fmt.Println("Protocol: ", ipv4.Protocol)
		fmt.Println("TTL: ", ipv4.TTL)
		fmt.Println("TOS: ", ipv4.TOS)
		fmt.Println("IHL: ", ipv4.IHL)
	}

	tcpLayer := (*packet).Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		fmt.Println("TCP layer detected.")
		tcp, _ := tcpLayer.(*layers.TCP)
		fmt.Printf("From port %d to %d", tcp.SrcPort, tcp.DstPort)
		fmt.Println("Sequence number: ", tcp.Seq)
		fmt.Println("ACK: ", tcp.Ack)
	}

	udpLayer := (*packet).Layer(layers.LayerTypeUDP)
	if udpLayer != nil {
		fmt.Println("UDP layer detected.")
		udp, _ := udpLayer.(*layers.UDP)
		fmt.Printf("From port %d to %d\n", udp.SrcPort, udp.DstPort)
		fmt.Println("Checksum number: ", udp.Checksum)
		fmt.Println()
	}

	applicationLayer := (*packet).ApplicationLayer()
	if applicationLayer != nil {
		fmt.Println("Application layer/Payload found.")
		fmt.Printf("%s\n", applicationLayer.Payload())

		if strings.Contains(string(applicationLayer.Payload()), "HTTP") {
			fmt.Println("HTTP found!")
		}
		if strings.Contains(string(applicationLayer.Payload()), "FTP") {
			fmt.Println("FTP found!")
		}
	}

	if err := (*packet).ErrorLayer(); err != nil {
		fmt.Println("Error decoding some part of the packet:", err)
	}

	fmt.Println("Press any key to inspect next packet")
	reader := bufio.NewReader(os.Stdin)
	text, _ := reader.ReadString('\n')
	text = strings.Replace(text, "\n", "", -1)

}
