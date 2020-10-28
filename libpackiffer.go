// +build linux

package main

// #cgo CFLAGS: -g -Wall
//#include <string.h>
//#include <stdio.h>
//#include <stdlib.h>
//#include <sys/socket.h>
//#include <linux/if_packet.h>
//#include <net/if_arp.h>
//#include <sys/time.h>
//#include <sys/types.h>
//#include <net/ethernet.h>
//#include <arpa/inet.h>
//#include <net/if.h>
//#include <sys/ioctl.h>
//#include <errno.h>
//#include <linux/ip.h>
//#include <netinet/udp.h>
//#include <netinet/tcp.h>
//#include <getopt.h>
//#include <stdbool.h>
//#include <ifaddrs.h>
//#include <ctype.h>
//#include <unistd.h>
//#include <poll.h>
//#include <signal.h>
//#include <sys/mman.h>
//#include <linux/ip.h>
//#include <linux/net_tstamp.h>
//#include <assert.h>
//#include <netdb.h>
//#include <sys/wait.h>
//#include <pthread.h>
//#include <sys/syscall.h>
import "C"
import (
	"fmt"
	"net"
	"syscall"
)

//GetInterfaceListAfPacket returns list of network interfaces has AF_PACKET family type
func GetInterfaceListAfPacket() {
	var addrs *C.struct_ifaddrs
	var tmp *C.struct_ifaddrs
	C.getifaddrs(&addrs)
	tmp = addrs
	for {
		if tmp.ifa_addr != nil && tmp.ifa_addr.sa_family == syscall.AF_PACKET {
			fmt.Println("interface name:" + C.GoString(tmp.ifa_name))
		}
		tmp = tmp.ifa_next
		if tmp == nil {
			break
		}
	}
	defer C.freeifaddrs(addrs)
}

// CreateSocket returns AF_PACKET socket file descriptor
func CreateSocket() (int, error) {
	psocket, perror := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, syscall.ETH_P_ALL)
	defer syscall.Close(psocket)
	if perror != nil {
		fmt.Println("Error: " + perror.Error())
		return psocket, perror
	}
	return psocket, perror
}

// GetInterfaceList returns list of network interfaces
func GetInterfaceList() {
	interfaceList, _ := net.Interfaces()
	if interfaceList != nil {
		for _, item := range interfaceList {
			fmt.Println(item.Name)
		}
	}
}

// SetPacketVersion set packet version to 3
func SetPacketVersion(socketDescriptor int) (int, error) {
	SolPacket := 263
	PacketVersion := 10
	PacketV3 := 2
	psetsockopt := syscall.SetsockoptInt(socketDescriptor, SolPacket, PacketVersion, PacketV3)
	if psetsockopt != nil {
		return 1, psetsockopt
	}
	return -1, psetsockopt
}
