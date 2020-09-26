// +build linux windows darwin freebsd netbsd openbsd

package packiffer

import (
	"fmt"
	"os"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcapgo"
)

func (p *packiffer) packetInfo(packet *gopacket.Packet) {
	ethernetLayer := (*packet).Layer(layers.LayerTypeEthernet)
	if ethernetLayer != nil {
		fmt.Println("Ethernet layer detected.")
		ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
		fmt.Println("Source MAC: ", ethernetPacket.SrcMAC)
		fmt.Println("Destination MAC: ", ethernetPacket.DstMAC)
		fmt.Println("Ethernet type: ", ethernetPacket.EthernetType)
		fmt.Println()
	}

	ipLayer := (*packet).Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		fmt.Println("IPv4 layer detected.")
		ip, _ := ipLayer.(*layers.IPv4)

		fmt.Printf("From %s to %s\n", ip.SrcIP, ip.DstIP)
		fmt.Println("Protocol: ", ip.Protocol)
		fmt.Println()
	}

	tcpLayer := (*packet).Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		fmt.Println("TCP layer detected.")
		tcp, _ := tcpLayer.(*layers.TCP)

		fmt.Printf("From port %d to %d\n", tcp.SrcPort, tcp.DstPort)
		fmt.Println("Sequence number: ", tcp.Seq)
		fmt.Println()
	}

	fmt.Println("All packet layers:")
	for _, layer := range (*packet).Layers() {
		fmt.Println("- ", layer.LayerType())
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
}

func (p *packiffer) dumpPacket(packets *gopacket.Packet) {
	var f *os.File
	if outputFlag == true {
		f, _ = os.Create(p.output + ".pcap")
	} else {
		f, _ = os.Create(p.interfaceName + ".pcap")
	}
	w := pcapgo.NewWriter(f)
	w.WriteFileHeader(snapshotLen, layers.LinkTypeEthernet)
	w.WritePacket((*packets).Metadata().CaptureInfo, (*packets).Data())
	packetCount++

	if limitFlag == true && (packetCount > int64(packetLimit)) {
		fmt.Printf("\n%d packets captured on %s", packetLimit, p.interfaceName)
		os.Exit(0)
	}
	defer f.Close()
}
