// +build linux windows darwin freebsd netbsd openbsd

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"
)

var snapshotLen uint32

type packiffer struct {
	interfaceName    string
	promiscuous      bool
	interfaceIndex   int
	filter           string
	socketDescriptor int
	input            string
	output           string
	device           bool
	snapshotLen      int32
	help             bool
	err              error
	timeout          time.Duration
	handle           *pcap.Handle
}

var interfaceNameFlag bool
var promiscuousFlag bool
var filterFlag bool
var inputFlag bool
var outputFlag bool
var helpFlag bool
var deviceFlag bool
var limitFlag bool
var timeoutFlag bool

var packetCount int64
var httpCount int64
var tcpCount int64
var udpCount int64
var ipCount int64
var arpCount int64
var ethCount int64
var otherCount int64
var dumpPackets bool
var displayPackets bool
var displayChart bool
var packetLimit int

func isFlagPassed(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

func ctrlCHandler() {
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		fmt.Println("\r- Ctrl+C pressed in Terminal")
		os.Exit(0)
	}()
}

func showhelp() {
	fmt.Printf("Usage of packiffer: \n")
	fmt.Printf("-i <interfaceName>\n\t\tinterface name to interact.\t e.g. -i eth0\n")
	fmt.Printf("-p\n\t\tpromiscuous mode\n")
	fmt.Printf("-f <filter>\n\t\tfilter query to set.\t e.g. -f all\n")
	fmt.Printf("-r <file>\n\t\tinput file to read.\t e.g. -r packet.pcap\n")
	fmt.Printf("-w <file>\n\t\toutput file to write.\t e.g. -w packet.pcap\n")
	fmt.Printf("-h\n\t\tdisplay help\n")
	fmt.Printf("-d\n\t\tdisplay list of devices\n")
	fmt.Printf("-c <file>\n\t\tlimit count of packets to sniff.\t e.g. -c 100\n")
	fmt.Printf("-t <value>\n\t\tlimit sniffing timeout.\t e.g. -t 30\n")

}

func checkFlagsPassed() {
	interfaceNameFlag = isFlagPassed("i")
	promiscuousFlag = isFlagPassed("p")
	filterFlag = isFlagPassed("f")
	inputFlag = isFlagPassed("r")
	outputFlag = isFlagPassed("w")
	helpFlag = isFlagPassed("h")
	deviceFlag = isFlagPassed("d")
	limitFlag = isFlagPassed("c")
	timeoutFlag = isFlagPassed("t")
}

func getFlagsValue() *packiffer {
	interfaceName := flag.String("i", "eth0", "Specify interface name. Default is eth0")
	promiscuous := flag.Bool("p", false, "Specify promiscuous mode. Default is false")
	filter := flag.String("f", "all", "Specify filter query. Default is all")
	input := flag.String("r", "input", "Specify input file name. Default is interfacename")
	output := flag.String("w", "output", "Specify output file name. Default is interfacename")
	help := flag.Bool("h", false, "Specify help display. Default is false")
	device := flag.Bool("d", true, "Specify devices display. Default is false")
	limit := flag.Int("c", 1000, "Limit count of packets to sniff. Default is 1000")
	timeout := flag.Int("t", 30, "limit sniffing timeout. Default is 30 seconds")

	packetLimit = *limit

	snapshotLen = 1024

	flag.Parse()

	return &packiffer{
		interfaceName: *interfaceName,
		promiscuous:   *promiscuous,
		filter:        *filter,
		input:         *input,
		output:        *output,
		device:        *device,
		snapshotLen:   1024,
		timeout:       time.Duration(*timeout) * time.Second,
		help:          *help}

}

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

	udpLayer := (*packet).Layer(layers.LayerTypeUDP)
	if udpLayer != nil {
		fmt.Println("UDP layer detected.")
		udp, _ := udpLayer.(*layers.UDP)

		fmt.Printf("From port %d to %d\n", udp.SrcPort, udp.DstPort)
		fmt.Println("Checksum number: ", udp.Checksum)
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
	if inputFlag == true && outputFlag == false {
		p.openInputPcap()
	}
	if outputFlag == true && inputFlag == false || outputFlag == false && inputFlag == false {
		p.openLivePcap()
	}
	if inputFlag == true && outputFlag == true {
		p.openTransformPcap()
	}
}

func (p *packiffer) openTransformPcap() {

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

func main() {

	ctrlCHandler()

	p := getFlagsValue()

	checkFlagsPassed()

	flag.Usage = func() {
		showhelp()
	}

	if helpFlag == true {
		showhelp()
		os.Exit(0)
	}

	p.pcap()

	os.Exit(0)
}
