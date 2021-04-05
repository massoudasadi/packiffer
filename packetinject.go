// +build linux windows darwin freebsd netbsd openbsd

package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"reflect"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type Packet struct {
	Ethernet EthernetHeader `json:"ethernetLayer"`
	Ip       IpHeader       `json:"ipLayer"`
	Tcp      TcpHeader      `json:"tcpLayer"`
	Payload  string         `json:"payload"`
}

type EthernetHeader struct {
	SrcMAC string `json:"SrcMAC"`
	DstMAC string `json:"DstMAC"`
}

type IpHeader struct {
	SrcIP string `json:"SrcIP"`
	DstIP string `json:"DstIP"`
}

type TcpHeader struct {
	SrcPort int `json:"SrcPort"`
	DstPort int `json:"DstPort"`
}

func (p *packiffer) injectPacket() {
	p.handle, p.err = pcap.OpenLive(p.interfaceName, p.snapshotLen, p.promiscuous, p.timeout)
	if p.err != nil {
		log.Fatal(p.err)
	}
	defer p.handle.Close()

	if p.Raw {
		file, err := os.ReadFile(p.File)
		if err != nil {
			log.Fatal(err)
			os.Exit(0)
		}
		p.err = p.handle.WritePacketData(file)
		if p.err != nil {
			log.Fatal(p.err)
		} else {
			fmt.Println("Packet injected successfully.")
		}
	}
	if p.Constructed {

		jsonFile, err := os.Open(p.File)
		if err != nil {
			fmt.Println(err)
		}
		fmt.Println("Successfully Opened file")
		defer jsonFile.Close()

		packetValue, _ := ioutil.ReadAll(jsonFile)

		var packet Packet

		json.Unmarshal(packetValue, &packet)

		var ethernetLayer *layers.Ethernet
		var ipLayer *layers.IPv4
		var tcpLayer *layers.TCP

		if !reflect.ValueOf(packet.Ethernet).IsZero() {

			if !reflect.ValueOf(packet.Ethernet.SrcMAC).IsZero() && !reflect.ValueOf(packet.Ethernet.DstMAC).IsZero() {
				srcMAC, err := net.ParseMAC(packet.Ethernet.SrcMAC)
				if err != nil {
					fmt.Println(err)
				}
				dstMAC, err := net.ParseMAC(packet.Ethernet.SrcMAC)
				if err != nil {
					fmt.Println(err)
				}
				ethernetLayer = &layers.Ethernet{
					SrcMAC: srcMAC,
					DstMAC: dstMAC,
				}
			}
			if !reflect.ValueOf(packet.Ethernet.SrcMAC).IsZero() && reflect.ValueOf(packet.Ethernet.DstMAC).IsZero() {
				srcMAC, err := net.ParseMAC(packet.Ethernet.SrcMAC)
				if err != nil {
					fmt.Println(err)
				}
				ethernetLayer = &layers.Ethernet{
					SrcMAC: srcMAC,
				}
			}
			if reflect.ValueOf(packet.Ethernet.SrcMAC).IsZero() && !reflect.ValueOf(packet.Ethernet.DstMAC).IsZero() {
				dstMAC, err := net.ParseMAC(packet.Ethernet.SrcMAC)
				if err != nil {
					fmt.Println(err)
				}
				ethernetLayer = &layers.Ethernet{
					DstMAC: dstMAC,
				}
			}
		}

		if !reflect.ValueOf(packet.Ip).IsZero() {

			if !reflect.ValueOf(packet.Ip.SrcIP).IsZero() && !reflect.ValueOf(packet.Ip.DstIP).IsZero() {
				ipLayer = &layers.IPv4{
					SrcIP: net.ParseIP(packet.Ip.SrcIP),
					DstIP: net.ParseIP(packet.Ip.DstIP),
				}
			}
			if !reflect.ValueOf(packet.Ip.SrcIP).IsZero() && reflect.ValueOf(packet.Ip.DstIP).IsZero() {
				ipLayer = &layers.IPv4{
					SrcIP: net.ParseIP(packet.Ip.SrcIP),
				}
			}
			if reflect.ValueOf(packet.Ip.SrcIP).IsZero() && !reflect.ValueOf(packet.Ip.DstIP).IsZero() {
				ipLayer = &layers.IPv4{
					DstIP: net.ParseIP(packet.Ip.DstIP),
				}
			}
		}

		if !reflect.ValueOf(packet.Tcp).IsZero() {

			if !reflect.ValueOf(packet.Tcp.SrcPort).IsZero() && !reflect.ValueOf(packet.Tcp.DstPort).IsZero() {
				tcpLayer = &layers.TCP{
					SrcPort: layers.TCPPort(packet.Tcp.SrcPort),
					DstPort: layers.TCPPort(packet.Tcp.DstPort),
				}
			}
			if !reflect.ValueOf(packet.Tcp.SrcPort).IsZero() && reflect.ValueOf(packet.Tcp.DstPort).IsZero() {
				tcpLayer = &layers.TCP{
					SrcPort: layers.TCPPort(packet.Tcp.SrcPort),
				}
			}
			if reflect.ValueOf(packet.Tcp.SrcPort).IsZero() && !reflect.ValueOf(packet.Tcp.DstPort).IsZero() {
				tcpLayer = &layers.TCP{
					DstPort: layers.TCPPort(packet.Tcp.DstPort),
				}
			}
		}

		p.buffer = gopacket.NewSerializeBuffer()
		rawBytes := []byte(packet.Payload)
		if !reflect.ValueOf(packet.Ethernet).IsZero() &&
			!reflect.ValueOf(packet.Ip).IsZero() &&
			!reflect.ValueOf(packet.Tcp).IsZero() {
			gopacket.SerializeLayers(p.buffer, p.options,
				ethernetLayer,
				ipLayer,
				tcpLayer,
				gopacket.Payload(rawBytes),
			)
		}
		if !reflect.ValueOf(packet.Ethernet).IsZero() &&
			!reflect.ValueOf(packet.Ip).IsZero() &&
			reflect.ValueOf(packet.Tcp).IsZero() {
			gopacket.SerializeLayers(p.buffer, p.options,
				ethernetLayer,
				ipLayer,
				gopacket.Payload(rawBytes),
			)
		}
		if !reflect.ValueOf(packet.Ethernet).IsZero() &&
			reflect.ValueOf(packet.Ip).IsZero() &&
			reflect.ValueOf(packet.Tcp).IsZero() {
			gopacket.SerializeLayers(p.buffer, p.options,
				ethernetLayer,
				gopacket.Payload(rawBytes),
			)
		}
		outgoingPacket := p.buffer.Bytes()
		p.err = p.handle.WritePacketData(outgoingPacket)
		if p.err != nil {
			log.Fatal(p.err)
		} else {
			fmt.Println("Packet injected successfully.")
		}
	}
}
