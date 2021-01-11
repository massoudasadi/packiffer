// +build linux windows darwin freebsd netbsd openbsd

package main

import (
	"fmt"
	"log"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

func (p *packiffer) openTransformPcap() {
	p.handle, p.err = pcap.OpenOffline(p.input)
	if p.err != nil {
		log.Fatal(p.err)
	}
	defer p.handle.Close()
	if transformFilterFlag == true {
		p.filterPacket()
	}
	packetCount = 0
	var f *os.File = nil
	var err error
	p.createTransformPcap(&f, err)
	w := pcapgo.NewWriter(f)
	w.WriteFileHeader(snapshotLen, layers.LinkTypeEthernet)
	defer f.Close()
	var wg sync.WaitGroup
	var mu sync.Mutex
	packetSource := gopacket.NewPacketSource(p.handle, p.handle.LinkType())
	for packet := range packetSource.Packets() {
		atomic.AddInt64(&packetCount, 1)
		wg.Add(1)
		go p.transformdumpPacket(packet, w, &wg, &mu)
		if packetCount > int64(p.limit) {
			break
		}
	}
	wg.Wait()
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
	var f *os.File = nil
	var err error
	p.createSniffPcap(&f, err)
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(snapshotLen, layers.LinkTypeEthernet); err != nil {
		fmt.Print("pcap.WriteFileHeader(): " + err.Error())
	}
	defer f.Close()
	go displayPacketCount()
	var wg sync.WaitGroup
	var mu sync.Mutex
	if snifflimitFlag == false {
		packets := gopacket.NewPacketSource(p.handle, p.handle.LinkType())
		for packet := range packets.Packets() {
			atomic.AddInt64(&packetCount, 1)
			wg.Add(1)
			go p.sniffdumpPacket(packet, w, &wg, &mu)
			if packetCount > 10000 {
				break
			}
		}
		wg.Wait()
	} else {
		packets := gopacket.NewPacketSource(p.handle, p.handle.LinkType())
		for packet := range packets.Packets() {
			atomic.AddInt64(&packetCount, 1)
			wg.Add(1)
			go p.sniffdumpPacket(packet, w, &wg, &mu)
			if packetCount > int64(p.limit) {
				break
			}
		}
		wg.Wait()
	}
}

func (p *packiffer) createSniffPcap(f **os.File, err error) {
	if sniffoutputdirectoryFlag == true && sniffoutputfilenameFlag == true {
		*f, err = os.Create(p.outputDirectory + "/" + p.outputFileName + ".pcap")
		if err != nil {
			fmt.Println("error in creating pcap file")
			os.Exit(0)
		}
		fmt.Println("packets dump in: " + p.outputDirectory + "/" + p.outputFileName + ".pcap")
	}
	if sniffoutputdirectoryFlag == false && sniffoutputfilenameFlag == true {
		*f, err = os.Create(p.outputFileName + ".pcap")
		if err != nil {
			fmt.Println("error in creating pcap file")
			os.Exit(0)
		}
		fmt.Println("packets dump in: " + p.outputFileName + ".pcap")
	}
	if sniffoutputdirectoryFlag == true && sniffoutputfilenameFlag == false {
		*f, err = os.Create(p.outputDirectory + "/" + p.interfaceName + ".pcap")
		if err != nil {
			fmt.Println("error in creating pcap file")
			os.Exit(0)
		}
		fmt.Println("packets dump in: " + p.outputDirectory + "/" + p.interfaceName + ".pcap")
	}
	if sniffoutputdirectoryFlag == false && sniffoutputfilenameFlag == false {
		*f, err = os.Create(p.interfaceName + ".pcap")
		if err != nil {
			fmt.Println("error in creating pcap file")
			os.Exit(0)
		}
		fmt.Println("packets dump in: " + p.interfaceName + ".pcap")
	}
}

func (p *packiffer) createTransformPcap(f **os.File, err error) {
	if transformoutputdirectoryFlag == true && transformoutputfilenameFlag == true {
		*f, err = os.Create(p.outputDirectory + "/" + p.outputFileName + ".pcap")
		if err != nil {
			fmt.Println("error in creating pcap file")
			os.Exit(0)
		}
		fmt.Println("packets dump in: " + p.outputDirectory + "/" + p.outputFileName + ".pcap")
	}
	if transformoutputdirectoryFlag == false && transformoutputfilenameFlag == true {
		*f, err = os.Create(p.outputFileName + ".pcap")
		if err != nil {
			fmt.Println("error in creating pcap file")
			os.Exit(0)
		}
		fmt.Println("packets dump in: " + p.outputFileName + ".pcap")
	}
	if transformoutputdirectoryFlag == true && transformoutputfilenameFlag == false {
		*f, err = os.Create(p.outputDirectory + "/" + p.interfaceName + ".pcap")
		if err != nil {
			fmt.Println("error in creating pcap file")
			os.Exit(0)
		}
		fmt.Println("packets dump in: " + p.outputDirectory + "/" + p.interfaceName + ".pcap")
	}
	if transformoutputdirectoryFlag == false && transformoutputfilenameFlag == false {
		*f, err = os.Create(p.interfaceName + ".pcap")
		if err != nil {
			fmt.Println("error in creating pcap file")
			os.Exit(0)
		}
		fmt.Println("packets dump in: " + p.interfaceName + ".pcap")
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
		p.packetInfo(&packet)
	}
}
