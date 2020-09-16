package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"fyne.io/fyne"
	"fyne.io/fyne/app"
	"fyne.io/fyne/canvas"
	"fyne.io/fyne/layout"
	"fyne.io/fyne/theme"
	"fyne.io/fyne/widget"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/google/gopacket/pcapgo"

	"github.com/wcharczuk/go-chart"
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
	engine           string
	device           bool
	snapshotLen      int32
	gui              bool
	help             bool
	err              error
	timeout          time.Duration
	handle           *pcap.Handle
	packetCount      int64
	httpCount        int64
	tcpCount         int64
	udpCount         int64
	ipCount          int64
	arpCount         int64
	ethCount         int64
	otherCount       int64
	dumpPackets      bool
	displayPackets   bool
	displayChart     bool
	packetLimit      int
}

var interfaceNameFlag bool
var promiscuousFlag bool
var filterFlag bool
var inputFlag bool
var outputFlag bool
var guiFlag bool
var helpFlag bool
var engineModeFlag bool
var deviceFlag bool
var limitFlag bool

func (p *packiffer) afpacket() {

}

func (p *packiffer) customafpacket() {
	fileDescriptor, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, syscall.ETH_P_ALL)
	if err != nil {
		fmt.Println("Error: " + err.Error())
		return
	}
	defer syscall.Close(fileDescriptor)
}

func (p *packiffer) pfring() {

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
	p.packetCount++

	if limitFlag == true && (p.packetCount > int64(p.packetLimit)) {
		fmt.Printf("\n%d packets captured on %s", p.packetLimit, p.interfaceName)
		os.Exit(0)
	}
	defer f.Close()
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

func isFlagPassed(name string) bool {
	found := false
	flag.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

func (p *packiffer) handleui() {
	a := app.New()
	a.Settings().SetTheme(theme.LightTheme())
	w := a.NewWindow("Packiffer")
	w.Resize(fyne.NewSize(800, 600))

	image := canvas.NewImageFromFile("/home/massoud/packiffer/packiffer.png")
	image.Resize(fyne.NewSize(600, 200))
	image.SetMinSize(fyne.NewSize(600, 200))

	logo := fyne.NewContainerWithLayout(layout.NewHBoxLayout(),
		layout.NewSpacer(), image, layout.NewSpacer())

	hello := widget.NewLabel("Cross-Platform Packet Sniffer")

	message := fyne.NewContainerWithLayout(layout.NewHBoxLayout(),
		layout.NewSpacer(), hello, layout.NewSpacer())

	button := widget.NewButton("Start Sniffing ...", func() {
		hello.SetText("Sniffing")
	})

	interfaceTextBox := widget.NewEntry()
	interfaceTextBox.SetPlaceHolder("Enter interface name ...")

	filterTextBox := widget.NewEntry()
	filterTextBox.SetPlaceHolder("Enter Filter ...")

	spaceContainer := fyne.NewContainerWithLayout(layout.NewGridWrapLayout(fyne.NewSize(30, 1)),
		widget.NewLabel(""))

	combo := widget.NewSelect([]string{"libpcap", "pfring", "afpacket"}, func(value string) {

	})
	combo.PlaceHolder = "Select Engine ..."

	container := fyne.NewContainerWithLayout(layout.NewHBoxLayout(),
		interfaceTextBox,
		spaceContainer,
		filterTextBox,
		spaceContainer,
		combo,
		spaceContainer,
		button)

	w.SetContent(fyne.NewContainerWithLayout(layout.NewVBoxLayout(),
		logo,
		message,
		widget.NewLabel(""),
		container))
	w.ShowAndRun()
}

func (p *packiffer) displaychart() {
	pie := chart.PieChart{
		Width:  512,
		Height: 512,
		Values: []chart.Value{
			{Value: float64(p.packetCount), Label: "ALL"},
			{Value: float64(p.udpCount), Label: "UDP"},
			{Value: float64(p.ipCount), Label: "IP"},
			{Value: float64(p.tcpCount), Label: "TCP"},
			{Value: float64(p.arpCount), Label: "ARP"},
			{Value: float64(p.ethCount), Label: "Ethernet"},
			{Value: float64(p.otherCount), Label: "Other"},
			{Value: float64(p.httpCount), Label: "HTTP"},
		},
	}
	chartOutput, _ := os.Create("chartOutput.png")
	defer chartOutput.Close()
	pie.Render(chart.PNG, chartOutput)
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
	fmt.Printf("-g\n\t\tgui mode\n")
	fmt.Printf("-h\n\t\tdisplay help\n")
	fmt.Printf("-e <engine>\n\t\tpacket capture engine can be libpcap (Cross-Platform), pfring (Linux Only) or afpacket (Linux Only). default is libpcap (libpcap implemented with AF_PACKET on linux).\t e.g. -e libpcap\n")
	fmt.Printf("-d\n\t\tdisplay list of devices\n")
	fmt.Printf("-c <file>\n\t\tlimit count of packets to sniff.\t e.g. -c 100\n")
}

func checkFlagsPassed() {
	interfaceNameFlag = isFlagPassed("i")
	promiscuousFlag = isFlagPassed("p")
	filterFlag = isFlagPassed("f")
	inputFlag = isFlagPassed("r")
	outputFlag = isFlagPassed("w")
	guiFlag = isFlagPassed("g")
	helpFlag = isFlagPassed("h")
	engineModeFlag = isFlagPassed("e")
	deviceFlag = isFlagPassed("d")
	limitFlag = isFlagPassed("c")
}

func getFlagsValue() packiffer {
	interfaceName := flag.String("i", "eth0", "Specify interface name. Default is eth0")
	promiscuous := flag.Bool("p", false, "Specify promiscuous mode. Default is false")
	filter := flag.String("f", "all", "Specify filter query. Default is all")
	input := flag.String("r", "input", "Specify input file name. Default is interfacename")
	output := flag.String("w", "output", "Specify output file name. Default is interfacename")
	gui := flag.Bool("g", false, "Specify gui mode. Default is false")
	help := flag.Bool("h", false, "Specify help display. Default is false")
	engineMode := flag.String("e", "libpcap", "Specify packet capture engine. Default is libpcap")
	device := flag.Bool("d", true, "Specify devices display. Default is false")
	limit := flag.Int("c", 1000, "Limit count of packets to sniff. Default is 1000")
	snapshotLen = 1024

	flag.Parse()

	return packiffer{
		interfaceName: *interfaceName,
		promiscuous:   *promiscuous,
		filter:        *filter,
		engine:        *engineMode,
		input:         *input,
		output:        *output,
		device:        *device,
		snapshotLen:   1024,
		timeout:       30 * time.Second,
		packetLimit:   *limit,
		gui:           *gui,
		help:          *help}

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

	if guiFlag == true {
		p.handleui()
		os.Exit(0)
	}

	switch runtime.GOOS {
	case "linux":
		if p.engine == "afpacket" {
			p.afpacket()
		} else if p.engine == "pfring" {
			p.pfring()
		} else if p.engine == "libpcap" {
			p.pcap()
		} else {
			fmt.Printf("\nUnknown engine using pcap instead")
			p.pcap()
		}
	case "windows":
		if p.engine == "afpacket" {
			fmt.Println(string("AF_PACKET not supported on Windows"))
			fmt.Printf("\nusing pcap instead")
			p.pcap()
		} else if p.engine == "pfring" {
			fmt.Println(string("PF_RING not supported on Windows"))
			fmt.Printf("\nusing pcap instead")
			p.pcap()
		} else if p.engine == "libpcap" {
			p.pcap()
		} else {
			fmt.Printf("\nUnknown engine using pcap instead")
			p.pcap()
		}
	case "darwin":
		if p.engine == "afpacket" {
			fmt.Println(string("AF_PACKET not supported on Mac"))
			fmt.Printf("\nusing pcap instead")
			p.pcap()
		} else if p.engine == "pfring" {
			fmt.Println(string("PF_RING not supported on Mac"))
			fmt.Printf("\nusing pcap instead")
			p.pcap()
		} else if p.engine == "libpcap" {
			p.pcap()
		} else {
			fmt.Printf("\nUnknown engine using pcap instead")
			p.pcap()
		}
	case "freebsd", "openbsd", "netbsd":
		if p.engine == "afpacket" {
			fmt.Println(string("AF_PACKET not supported on BSD"))
			fmt.Printf("\nusing pcap instead")
			p.pcap()
		} else if p.engine == "pfring" {
			fmt.Println(string("PF_RING not supported on BSD"))
			fmt.Printf("\nusing pcap instead")
			p.pcap()
		} else if p.engine == "libpcap" {
			p.pcap()
		} else {
			fmt.Printf("\nUnknown engine using pcap instead")
			p.pcap()
		}
	default:
		fmt.Printf("%s not supported.\n", runtime.GOOS)
		os.Exit(0)
	}

	os.Exit(0)
}
