// +build linux windows darwin freebsd netbsd openbsd

package packiffer

import (
	"fmt"
	"log"
	"os"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
)

func (p *packiffer) injectPacket() {

}

func (p *packiffer) pcap() {
	if deviceFlag == true {
		devices, err := pcap.FindAllDevs()
		if err != nil {
			log.Fatal(err)
		}
		p.displayDevices(devices)
		os.Exit(0)
	}
	if inputFlag == true {
		p.openInputPcap()
	}
	p.openLivePcap()
}

func (p *packiffer) openLivePcap() {
	p.handle, p.err = pcap.OpenLive(p.interfaceName, p.snapshotLen, p.promiscuous, p.timeout)
	if p.err != nil {
		log.Fatal(p.err)
	}
	defer p.handle.Close()
	if filterFlag == true {
		p.filterPacket()
	}
	packets := gopacket.NewPacketSource(p.handle, p.handle.LinkType())
	for packet := range packets.Packets() {
		//go p.packetInfo(&packet)
		go p.dumpPacket(&packet)
	}
}

func (p *packiffer) filterPacket() {
	p.err = p.handle.SetBPFFilter(p.filter)
	if p.err != nil {
		log.Fatal(p.err)
	}
}

func (p *packiffer) openInputPcap() {
	p.handle, p.err = pcap.OpenOffline(p.input)
	if p.err != nil {
		log.Fatal(p.err)
	}
	defer p.handle.Close()

	packetSource := gopacket.NewPacketSource(p.handle, p.handle.LinkType())
	for packet := range packetSource.Packets() {
		go p.packetInfo(&packet)
	}
}

func (p packiffer) displayDevices(devices []pcap.Interface) {
	fmt.Println("Devices found:")
	fmt.Printf("\n")
	for _, device := range devices {
		fmt.Println("Name: ", device.Name)
		fmt.Println("Description: ", device.Description)
		fmt.Println("Devices addresses: ")
		for _, address := range device.Addresses {
			fmt.Println("\t- IP address: ", address.IP)
			fmt.Println("\t- Subnet mask: ", address.Netmask)
		}
		fmt.Printf("\n")
	}
}
