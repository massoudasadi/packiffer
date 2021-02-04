// +build linux windows darwin freebsd netbsd openbsd

package main

import (
	"fmt"
	"log"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

func (p *packiffer) injectPacket() {
	p.handle, p.err = pcap.OpenLive(p.interfaceName, p.snapshotLen, p.promiscuous, p.timeout)
	if p.err != nil {
		log.Fatal(p.err)
	}
	defer p.handle.Close()
	if p.Raw == true {
		rawBytes := []byte{10, 20, 30}
		p.err = p.handle.WritePacketData(rawBytes)
		if p.err != nil {
			log.Fatal(p.err)
		} else {
			fmt.Println("Packet injected successfully.")
		}
	}
	if p.Constructed == true {
		ethernetLayer := &layers.Ethernet{
			SrcMAC: net.HardwareAddr{0xFF, 0xAA, 0xFA, 0xAA, 0xFF, 0xAA},
			DstMAC: net.HardwareAddr{0xBD, 0xBD, 0xBD, 0xBD, 0xBD, 0xBD},
		}
		ipLayer := &layers.IPv4{
			SrcIP: net.IP{127, 0, 0, 1},
			DstIP: net.IP{8, 8, 8, 8},
		}
		tcpLayer := &layers.TCP{
			SrcPort: layers.TCPPort(4321),
			DstPort: layers.TCPPort(80),
		}
		p.buffer = gopacket.NewSerializeBuffer()
		rawBytes := []byte{10, 20, 30}
		gopacket.SerializeLayers(p.buffer, p.options,
			ethernetLayer,
			ipLayer,
			tcpLayer,
			gopacket.Payload(rawBytes),
		)
		outgoingPacket := p.buffer.Bytes()
		p.err = p.handle.WritePacketData(outgoingPacket)
		if p.err != nil {
			log.Fatal(p.err)
		}
	}
}
