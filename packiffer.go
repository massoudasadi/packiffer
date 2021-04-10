// +build linux windows darwin freebsd netbsd openbsd

package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/google/gopacket"
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
	Raw              bool
	Constructed      bool
	File             string
	buffer           gopacket.SerializeBuffer
	options          gopacket.SerializeOptions
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

var injectInterface bool
var injectRaw bool
var injectConstruct bool
var injectFile bool

var firewallInterface bool
var firewallFile bool

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

func isFlagPassed(name string, FlagSet *flag.FlagSet) bool {
	found := false
	FlagSet.Visit(func(f *flag.Flag) {
		if f.Name == name {
			found = true
		}
	})
	return found
}

func (p *packiffer) ctrlCHandler() {
	c := make(chan os.Signal)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-c
		fmt.Println("\r- Ctrl+C pressed in Terminal")
		if p.mode == "firewall" {

			for i := 0; i < len(ipList); i++ {

				cmd := exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name="+ipList[0])

				cmd.Stdin = os.Stdin
				cmd.Stdout = os.Stdout
				cmd.Stderr = os.Stderr

				errs := cmd.Run()

				if errs != nil {
					fmt.Printf("%s\n", errs.Error())
					os.Exit(1)
				}

			}
		}
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

func checkSniffFlagsPassed(flag *flag.FlagSet) {
	sniffInterfaceNameFlag = isFlagPassed("i", flag)
	sniffPromiscuousFlag = isFlagPassed("p", flag)
	sniffFilterFlag = isFlagPassed("f", flag)
	sniffoutputdirectoryFlag = isFlagPassed("od", flag)
	sniffoutputfilenameFlag = isFlagPassed("of", flag)
	sniffsnapshotlengthFlag = isFlagPassed("sl", flag)
	snifftimeoutFlag = isFlagPassed("t", flag)
	snifflimitFlag = isFlagPassed("c", flag)
}

func checkTransformFlagsPassed(flag *flag.FlagSet) {
	transformFilterFlag = isFlagPassed("f", flag)
	transformInputFlag = isFlagPassed("in", flag)
	transformoutputdirectoryFlag = isFlagPassed("od", flag)
	transformoutputfilenameFlag = isFlagPassed("of", flag)
	transformlimitFlag = isFlagPassed("c", flag)
}

func checkInspectFlagsPassed(flag *flag.FlagSet) {
	inspectInputFlag = isFlagPassed("in", flag)
	inspectFilterFlag = isFlagPassed("f", flag)
	inspectlimitFlag = isFlagPassed("c", flag)
}

func checkInjectFlagsPassed(flag *flag.FlagSet) {
	injectInterface = isFlagPassed("i", flag)
	injectRaw = isFlagPassed("ir", flag)
	injectConstruct = isFlagPassed("ic", flag)
	injectFile = isFlagPassed("f", flag)
}

func checkFirewallFlagsPassed(flag *flag.FlagSet) {
	firewallInterface = isFlagPassed("i", flag)
	firewallFile = isFlagPassed("f", flag)
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
	snifflimit := sniffCommand.Int("c", 10000, "Limit count of packets to sniff. Default is 10000")

	transformCommand := flag.NewFlagSet("transform", flag.ExitOnError)
	transformFilter := transformCommand.String("f", "all", "Specify filter query. Default is all")
	transformInput := transformCommand.String("in", "", "Specify input pcap file")
	transformoutputdirectory := transformCommand.String("od", "packiffer", "Specify output directory. Default is packiffer directory")
	transformoutputfilename := transformCommand.String("of", "interface", "Specify output file name. Default is interface name")
	transformlimit := transformCommand.Int("c", 10000, "Limit count of packets to sniff. Default is 10000")

	inspectCommand := flag.NewFlagSet("inspect", flag.ExitOnError)
	inspectInput := inspectCommand.String("in", "", "Specify input pcap file")
	inspectFilter := inspectCommand.String("f", "all", "Specify filter query. Default is all")
	inspectlimit := inspectCommand.Int("c", 10000, "Limit count of packets to sniff. Default is 10000")

	injectCommand := flag.NewFlagSet("inject", flag.ExitOnError)
	injectInterface := injectCommand.String("i", "eth0", "Specify interface name. Default is eth0")
	injectRaw := injectCommand.Bool("ir", false, "Specify Raw Packet Inject. Default is false")
	injectConstruct := injectCommand.Bool("ic", false, "Specify Constructed Packet Inject. Default is False")
	injectFile := injectCommand.String("f", "inject.txt", "Specify Path to packet file. Default is inject.txt")

	firewallCommand := flag.NewFlagSet("firewall", flag.ExitOnError)
	fireWallInterface := firewallCommand.String("i", "eth0", "Specify interface name. Default is eth0")
	fireWallFile := firewallCommand.String("f", "firewall.txt", "Specify Path to firewall file. Default is firewall.txt")

	help := flag.Bool("h", false, "Specify help display. Default is false")
	device := flag.Bool("d", false, "Specify devices display. Default is false")

	flag.Parse()

	if *help {
		showhelp()
		os.Exit(0)
	}

	if *device {
		display()
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
		checkSniffFlagsPassed(sniffCommand)
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
		transformCommand.Parse(os.Args[2:])
		packetLimit = *transformlimit
		checkTransformFlagsPassed(transformCommand)
		return &packiffer{
			filter:          *transformFilter,
			outputDirectory: *transformoutputdirectory,
			outputFileName:  *transformoutputfilename,
			device:          *device,
			limit:           *transformlimit,
			mode:            "transform",
			input:           *transformInput,
			help:            *help}

	case "inspect":
		inspectCommand.Parse(os.Args[2:])
		checkInspectFlagsPassed(inspectCommand)
		return &packiffer{
			filter: *inspectFilter,
			device: *device,
			limit:  *inspectlimit,
			mode:   "inspect",
			input:  *inspectInput,
			help:   *help}

	case "inject":
		injectCommand.Parse(os.Args[2:])
		checkInjectFlagsPassed(injectCommand)
		return &packiffer{
			interfaceName: *injectInterface,
			Raw:           *injectRaw,
			Constructed:   *injectConstruct,
			File:          *injectFile,
			device:        *device,
			mode:          "inject",
			help:          *help}

	case "firewall":
		injectCommand.Parse(os.Args[2:])
		checkFirewallFlagsPassed(firewallCommand)
		return &packiffer{
			interfaceName: *fireWallInterface,
			File:          *fireWallFile,
			device:        *device,
			mode:          "firewall",
			help:          *help}
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
		fmt.Printf("\nStarting Packiffer in transform mode\n")
		p.openTransformPcap()
	}
	if mode == "inspect" {
		fmt.Printf("\nStarting Packiffer in inspect mode\n")
		p.openInputPcap()
	}
	if mode == "inject" {
		fmt.Printf("\nStarting Packiffer in inject mode\n")
		p.injectPacket()
	}
	if mode == "firewall" {
		fmt.Printf("\nStarting Packiffer in firewall mode\n")
		p.firewall()
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

func RunCommandCh(stdoutCh chan<- string, cutset string, command string, flags ...string) error {
	cmd := exec.Command(command, flags...)

	output, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("RunCommand: cmd.StdoutPipe(): %v", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("RunCommand: cmd.Start(): %v", err)
	}

	go func() {
		defer close(stdoutCh)
		for {
			buf := make([]byte, 1024)
			n, err := output.Read(buf)
			if err != nil {
				if err != io.EOF {
					log.Fatal(err)
				}
				if n == 0 {
					break
				}
			}
			text := strings.TrimSpace(string(buf[:n]))
			for {
				// Take the index of any of the given cutset
				n := strings.IndexAny(text, cutset)
				if n == -1 {
					// If not found, but still have data, send it
					if len(text) > 0 {
						stdoutCh <- text
					}
					break
				}
				// Send data up to the found cutset
				stdoutCh <- text[:n]
				// If cutset is last element, stop there.
				if n == len(text) {
					break
				}
				// Shift the text and start again.
				text = text[n+1:]
			}
		}
	}()

	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("RunCommand: cmd.Wait(): %v", err)
	}
	return nil
}

func main() {

	p := getFlagsValue()

	p.ctrlCHandler()

	if p == nil {
		os.Exit(0)
	}

	flag.Usage = func() {
		showhelp()
	}

	if helpFlag {
		showhelp()
		os.Exit(0)
	}

	p.pcap(p.mode)

	os.Exit(0)
}
