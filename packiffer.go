// +build linux windows darwin freebsd netbsd openbsd

package packiffer

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"github.com/google/gopacket/pcap"
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
	engine           string
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
var engineModeFlag bool

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
	fmt.Printf("-e <engine>\n\t\tpacket capture engine can be libpcap (Cross-Platform), pfring (Linux Only) or afpacket (Linux Only). default is libpcap (libpcap implemented with AF_PACKET on linux).\t e.g. -e libpcap\n")
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
	engineModeFlag = isFlagPassed("e")
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
	engineMode := flag.String("e", "libpcap", "Specify packet capture engine. Default is libpcap")

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
		engine:        *engineMode,
		timeout:       time.Duration(*timeout) * time.Second,
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
