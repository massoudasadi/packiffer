// +build linux windows darwin freebsd netbsd openbsd

package main

import (
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"
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
	if transformFilterFlag {
		p.filterPacket()
	}
	packetCount = 0
	var f *os.File = nil
	p.createTransformPcap(&f)
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
	if runtime.GOOS == "windows" {
		p.setInterfaceFriendlyName()
	}
	p.handle, p.err = pcap.OpenLive(p.interfaceName, p.snapshotLen, p.promiscuous, p.timeout)
	if p.err != nil {
		log.Fatal(p.err)
	}
	defer p.handle.Close()
	if sniffFilterFlag {
		p.filterPacket()
	}
	packetCount = 0
	var f *os.File = nil
	p.createSniffPcap(&f)
	w := pcapgo.NewWriter(f)
	if err := w.WriteFileHeader(snapshotLen, layers.LinkTypeEthernet); err != nil {
		fmt.Print("pcap.WriteFileHeader(): " + err.Error())
	}
	defer f.Close()
	go displayPacketCount()
	var wg sync.WaitGroup
	var mu sync.Mutex
	if snifflimitFlag {
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

func (p *packiffer) createSniffPcap(f **os.File) {
	var err error
	if sniffoutputdirectoryFlag && sniffoutputfilenameFlag {
		*f, err = os.Create(p.outputDirectory + "/" + p.outputFileName + ".pcap")
		if err != nil {
			fmt.Println("error in creating pcap file")
			os.Exit(0)
		}
		fmt.Println("packets dump in: " + p.outputDirectory + "/" + p.outputFileName + ".pcap")
	}
	if !sniffoutputdirectoryFlag && sniffoutputfilenameFlag {
		*f, err = os.Create(p.outputFileName + ".pcap")
		if err != nil {
			fmt.Println("error in creating pcap file")
			os.Exit(0)
		}
		fmt.Println("packets dump in: " + p.outputFileName + ".pcap")
	}
	if sniffoutputdirectoryFlag && !sniffoutputfilenameFlag {
		if runtime.GOOS == "windows" {
			*f, err = os.Create(p.outputDirectory + "/" + strings.TrimSpace(p.interfaceFriendlyName) + ".pcap")
			if err != nil {
				fmt.Println("error in creating pcap file")
				os.Exit(0)
			}
			fmt.Println("packets dump in: " + p.outputDirectory + "/" + strings.TrimSpace(p.interfaceFriendlyName) + ".pcap")
		} else {
			*f, err = os.Create(p.outputDirectory + "/" + p.interfaceName + ".pcap")
			if err != nil {
				fmt.Println("error in creating pcap file")
				os.Exit(0)
			}
			fmt.Println("packets dump in: " + p.outputDirectory + "/" + p.interfaceName + ".pcap")
		}
	}
	if !sniffoutputdirectoryFlag && !sniffoutputfilenameFlag {
		if runtime.GOOS == "windows" {
			*f, err = os.Create(strings.TrimSpace(p.interfaceFriendlyName) + ".pcap")
			if err != nil {
				fmt.Println("error in creating pcap file")
				os.Exit(0)
			}
			fmt.Println("packets dump in: " + strings.TrimSpace(p.interfaceFriendlyName) + ".pcap")
		} else {
			*f, err = os.Create(p.interfaceName + ".pcap")
			if err != nil {
				fmt.Println("error in creating pcap file")
				os.Exit(0)
			}
			fmt.Println("packets dump in: " + p.interfaceName + ".pcap")
		}
	}
}

func (p *packiffer) createTransformPcap(f **os.File) {
	var err error
	if transformoutputdirectoryFlag && transformoutputfilenameFlag {
		*f, err = os.Create(p.outputDirectory + "/" + p.outputFileName + ".pcap")
		if err != nil {
			fmt.Println("error in creating pcap file")
			os.Exit(0)
		}
		fmt.Println("packets dump in: " + p.outputDirectory + "/" + p.outputFileName + ".pcap")
	}
	if !transformoutputdirectoryFlag && transformoutputfilenameFlag {
		*f, err = os.Create(p.outputFileName + ".pcap")
		if err != nil {
			fmt.Println("error in creating pcap file")
			os.Exit(0)
		}
		fmt.Println("packets dump in: " + p.outputFileName + ".pcap")
	}
	if transformoutputdirectoryFlag && !transformoutputfilenameFlag {
		dt := time.Now()
		*f, err = os.Create(p.outputDirectory + "/" + dt.Format("02-11-1979-17:06:06") + ".pcap")
		if err != nil {
			fmt.Println("error in creating pcap file")
			os.Exit(0)
		}
		fmt.Println("packets dump in: " + p.outputDirectory + "/" + dt.Format("02-11-1979-17:06:06") + ".pcap")
	}
	if !transformoutputdirectoryFlag && !transformoutputfilenameFlag {
		dt := time.Now()
		*f, err = os.Create(dt.Format("02-11-1979-17:06:06") + ".pcap")
		if err != nil {
			fmt.Println("error in creating pcap file")
			os.Exit(0)
		}
		fmt.Println("packets dump in: " + dt.Format("02-11-1979-17:06:06") + ".pcap")
	}
}

func displayPacketCount() {
	ticker := time.Tick(time.Second)
	for {
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
