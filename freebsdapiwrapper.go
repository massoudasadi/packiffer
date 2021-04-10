// +build freebsd

package main

func displayFriendlyInterfaceName() {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		log.Fatal(err)
	}
	displayDevices(devices)
	os.Exit(0)
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

func display() {
	displayFriendlyInterfaceName()
}
