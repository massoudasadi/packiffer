// +build linux windows darwin freebsd netbsd openbsd

package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
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
	outputFileName   string
	outputDirectory  string
	limit            int
	device           bool
	snapshotLen      int32
	help             bool
	err              error
	timeout          time.Duration
	handle           *pcap.Handle
	mode             string
}

var sniffInterfaceNameFlag bool
var sniffPromiscuousFlag bool
var sniffFilterFlag bool
var sniffoutputdirectoryFlag bool
var sniffoutputfilenameFlag bool
var sniffsnapshotlengthFlag bool
var snifftimeoutFlag bool
var snifflimitFlag bool

var transformInterfaceNameFlag bool
var transformFilterFlag bool
var transformInputFlag bool
var transformoutputdirectoryFlag bool
var transformoutputfilenameFlag bool
var transformlimitFlag bool

var inspectInputFlag bool
var inspectFilterFlag bool
var inspectlimitFlag bool

var helpFlag bool
var deviceFlag bool

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
		fmt.Println("packets successfully dumped")
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
	sniffInterfaceNameFlag = isFlagPassed("i")
	sniffPromiscuousFlag = isFlagPassed("p")
	sniffFilterFlag = isFlagPassed("f")
	sniffoutputdirectoryFlag = isFlagPassed("od")
	sniffoutputfilenameFlag = isFlagPassed("of")
	sniffsnapshotlengthFlag = isFlagPassed("sl")
	snifftimeoutFlag = isFlagPassed("t")
	snifflimitFlag = isFlagPassed("c")
}

func getFlagsValue() *packiffer {

	sniffCommand := flag.NewFlagSet("sniff", flag.ExitOnError)
	sniffInterfaceName := sniffCommand.String("i", "eth0", "Specify interface name. Default is eth0")
	sniffPromiscuous := sniffCommand.Bool("p", false, "Specify promiscuous mode. Default is false")
	sniffFilter := sniffCommand.String("f", "all", "Specify filter query. Default is all")
	sniffoutputdirectory := sniffCommand.String("od", "packiffer", "Specify output directory. Default is packiffer directory")
	sniffoutputfilename := sniffCommand.String("of", "interface", "Specify output file name. Default is interface name")
	sniffsnapshotlength := sniffCommand.Int("sl", 1024, "Specify Snapshot Lenght. Default is 2014")
	snifftimeout := sniffCommand.Int("t", 30, "limit sniffing timeout. Default is 30 seconds")
	snifflimit := sniffCommand.Int("c", 1000, "Limit count of packets to sniff. Default is 1000")

	// transformCommand := flag.NewFlagSet("transform", flag.ExitOnError)
	// transformInterfaceName := transformCommand.String("i", "eth0", "Specify interface name. Default is eth0")
	// transformFilter := transformCommand.String("f", "all", "Specify filter query. Default is all")
	// transformInput := transformCommand.String("in", "", "Specify input pcap file")
	// transformoutputdirectory := transformCommand.String("od", "packiffer", "Specify output directory. Default is packiffer directory")
	// transformoutputfilename := transformCommand.String("of", "interface", "Specify output file name. Default is interface name")
	// transformlimit := transformCommand.Int("c", 1000, "Limit count of packets to sniff. Default is 1000")

	// inspectCommand := flag.NewFlagSet("inspect", flag.ExitOnError)
	// inspectInput := inspectCommand.String("in", "", "Specify input pcap file")
	// inspectFilter := inspectCommand.String("f", "all", "Specify filter query. Default is all")
	// inspectlimit := inspectCommand.Int("c", 1000, "Limit count of packets to sniff. Default is 1000")

	help := flag.Bool("h", false, "Specify help display. Default is false")
	device := flag.Bool("d", true, "Specify devices display. Default is false")

	flag.Parse()

	if helpFlag == true {
		showhelp()
		os.Exit(0)
	}

	if deviceFlag == true {
		devices, err := pcap.FindAllDevs()
		if err != nil {
			log.Fatal(err)
		}
		displayDevices(devices)
		os.Exit(0)
	}

	if len(os.Args) < 1 {
		showhelp()
		os.Exit(0)
	}

	switch os.Args[1] {

	case "sniff":
		sniffCommand.Parse(os.Args[2:])
		packetLimit = *snifflimit
		return &packiffer{
			interfaceName:   *sniffInterfaceName,
			promiscuous:     *sniffPromiscuous,
			filter:          *sniffFilter,
			outputDirectory: *sniffoutputdirectory,
			outputFileName:  *sniffoutputfilename,
			device:          *device,
			snapshotLen:     int32(*sniffsnapshotlength),
			timeout:         time.Duration(*snifftimeout) * time.Second,
			limit:           *snifflimit,
			mode:            "sniff",
			help:            *help}
	case "transform":

	case "inspect":

	default:
		showhelp()
		os.Exit(0)
	}
	return nil
}

func (p *packiffer) pcap(mode string) {
	if mode == "sniff" {
		fmt.Printf("\nStarting Packiffer in sniffing mode\n")
		p.openLivePcap()
	}
	if mode == "transform" {
		p.openTransformPcap()
	}
	if mode == "inspect" {
		p.openInputPcap()
	}
}

func exists(path string) (bool, error) {
	_, err := os.Stat(path)
	if err == nil {
		return true, nil
	}
	if os.IsNotExist(err) {
		return false, nil
	}
	return false, err
}

func displayDevices(devices []pcap.Interface) {
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

	if p == nil {
		os.Exit(0)
	}

	p.handleui()

	checkFlagsPassed()

	flag.Usage = func() {
		showhelp()
	}

	if helpFlag == true {
		showhelp()
		os.Exit(0)
	}

	p.pcap(p.mode)

	os.Exit(0)
}
