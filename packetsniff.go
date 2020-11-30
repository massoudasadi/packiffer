// +build linux windows darwin freebsd netbsd openbsd

package main

import (
	"fmt"
	"log"
	"os"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

func (p *packiffer) openTransformPcap() {

}

func (p *packiffer) openLivePcap() {
	p.handle, p.err = pcap.OpenLive(p.interfaceName, p.snapshotLen, p.promiscuous, p.timeout)
	if p.err != nil {
		log.Fatal(p.err)
	}
	defer p.handle.Close()
	if sniffFilterFlag == true {
		p.filterPacket()
	}
	packetCount = 0
	var f *os.File
	var err error
	p.createPcap(f, err)
	w := pcapgo.NewWriter(f)
	w.WriteFileHeader(snapshotLen, layers.LinkTypeEthernet)
	defer f.Close()
	go displayPacketCount()
	if snifflimitFlag == false {
		packets := gopacket.NewPacketSource(p.handle, p.handle.LinkType())
		for packet := range packets.Packets() {
			go p.dumpPacket(&packet, w)
		}
	} else {
		packets := gopacket.NewPacketSource(p.handle, p.handle.LinkType())
		for packet := range packets.Packets() {
			go p.dumpPacketWithLimit(&packet, w)
		}
	}
}

func (p *packiffer) createPcap(f *os.File, err error) {
	if sniffoutputdirectoryFlag == true && sniffoutputfilenameFlag == true {
		f, err = os.Create(p.outputDirectory + "/" + p.outputFileName + ".pcap")
		if err != nil {
			fmt.Println("error in creating pcap file")
			os.Exit(0)
		}
		fmt.Println("packets dump in: " + p.outputDirectory + "/" + p.outputFileName + ".pcap")
	}
	if sniffoutputdirectoryFlag == false && sniffoutputfilenameFlag == true {
		f, err = os.Create(p.outputFileName + ".pcap")
		if err != nil {
			fmt.Println("error in creating pcap file")
			os.Exit(0)
		}
		fmt.Println("packets dump in: " + p.outputFileName + ".pcap")
	}
	if sniffoutputdirectoryFlag == true && sniffoutputfilenameFlag == false {
		f, err = os.Create(p.outputDirectory + "/" + p.interfaceName + ".pcap")
		if err != nil {
			fmt.Println("error in creating pcap file")
			os.Exit(0)
		}
		fmt.Println("packets dump in: " + p.outputDirectory + "/" + p.interfaceName + ".pcap")
	}
	if sniffoutputdirectoryFlag == false && sniffoutputfilenameFlag == false {
		f, err = os.Create(p.interfaceName + ".pcap")
		if err != nil {
			fmt.Println("error in creating pcap file")
			os.Exit(0)
		}
		fmt.Println("packets dumpp in: " + p.interfaceName + ".pcap")
	}
}

func displayPacketCount() {
	ticker := time.Tick(time.Second)
	for true {
		<-ticker
		fmt.Printf("\033[2K\r%s%d", "packets sniffed: ", packetCount)
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
