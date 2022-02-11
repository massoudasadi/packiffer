// +build windows

package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"strings"

	"github.com/google/gopacket/pcap"
)

type Interface struct {
	Name         string
	Description  string
	Flags        uint32
	Addresses    []pcap.InterfaceAddress
	FriendlyName string
}

type InterfaceAddress struct {
	IP        net.IP
	Netmask   net.IPMask
	Broadaddr net.IP
	P2P       net.IP
}

var deviceListGlobal []Interface

func (p *packiffer) setInterfaceFriendlyName() {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}
	var deviceList = compare(devices)
	deviceListGlobal = deviceList
	for _, element := range deviceListGlobal {
		if element.Name == p.interfaceName {
			p.interfaceFriendlyName = element.FriendlyName
		}
	}
}

func displayFriendlyInterfaceName() {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}
	var deviceList = compare(devices)
	deviceListGlobal = deviceList
	displayDevices(deviceList)
	os.Exit(0)
}

func displayDevices(devices []Interface) {
	fmt.Println("Devices found:")
	fmt.Printf("\n")
	for _, device := range devices {
		fmt.Println("Name: ", device.Name)
		fmt.Println("FriendlyName: ", device.FriendlyName)
		fmt.Println("Description: ", device.Description)
		fmt.Println("Devices addresses: ")
		for _, address := range device.Addresses {
			fmt.Println("\t- IP address: ", address.IP)
			fmt.Println("\t- Subnet mask: ", address.Netmask)
		}
		fmt.Printf("\n")
	}
}

func compare(devices []pcap.Interface) []Interface {
	interfaceList := []Interface{}
	var mac = getmac()
	var ni = networkInterfaceList()
	for key, element := range mac {
		for _, d := range ni {
			if strings.ReplaceAll(strings.ToUpper(d.HardwareAddr.String()), ":", "-") == key {
				for _, device := range devices {
					if strings.Contains(device.Name, match(element[0])) {
						var interfaceElement = Interface{
							Name:         device.Name,
							FriendlyName: d.Name,
							Description:  device.Description,
							Flags:        device.Flags,
							Addresses:    device.Addresses,
						}
						interfaceList = append(interfaceList, interfaceElement)
					}
				}
			}
		}
	}
	return interfaceList
}

func match(s string) string {
	i := strings.Index(s, "{")
	if i >= 0 {
		j := strings.Index(s, "}")
		if j >= 0 {
			return s[i+1 : j]
		}
	}
	return ""
}

func getmac() map[string][]string {

	ch := make(chan string)
	go func() {
		err := RunCommandCh(ch, "\r\n", "getmac")
		if err != nil {
			log.Fatal(err)
		}
	}()

	var getmacarray []string

	for v := range ch {
		if strings.Count(v, "-") == 5 {
			getmacarray = append(getmacarray, v)
		}
		if strings.Contains(v, "\\Device") {
			getmacarray = append(getmacarray, v)
		}
	}

	x := make(map[string][]string)

	for i := 0; i <= len(getmacarray)-1; {
		if i+1 <= len(getmacarray)-1 && strings.Contains(getmacarray[i+1], "\\Device") {
			x[getmacarray[i]] = append(x[getmacarray[i]], getmacarray[i+1])
		}
		i = i + 1
	}

	return x
}

func networkInterfaceList() []net.Interface {
	ifaces, err := net.Interfaces()
	if err != nil {
		fmt.Println(fmt.Errorf("localAddresses: %+v", err.Error()))
		return nil
	}
	return ifaces
}

func display() {
	displayFriendlyInterfaceName()
}
