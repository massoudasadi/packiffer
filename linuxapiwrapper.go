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
	"errors"
	"fmt"
	"net"
	"syscall"
	"unsafe"
)

func getInterfaceListAfPacket() {
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

func createSocket() (int, error) {
	psocket, perror := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, syscall.ETH_P_ALL)
	defer syscall.Close(psocket)
	if perror != nil {
		fmt.Println("Error: " + perror.Error())
		return psocket, perror
	}
	return psocket, perror
}

func getInterfaceList() {
	interfaceList, _ := net.Interfaces()
	if interfaceList != nil {
		for _, item := range interfaceList {
			fmt.Println(item.Name)
		}
	}
}

func getInterfaceNames() []string {
	var ilist []string
	interfaceList, _ := net.Interfaces()
	if interfaceList != nil {
		for _, item := range interfaceList {
			ilist = append(ilist, item.Name)
		}
	}
	return ilist
}

func setPacketVersionV3(socketDescriptor int) (int, error) {
	PacketVersion := 10 // PACKET_VERSION
	PacketV3 := 2       // TPACKET_V3
	psetsockopt := syscall.SetsockoptInt(socketDescriptor, syscall.SOL_PACKET, PacketVersion, PacketV3)
	if psetsockopt != nil {
		return 1, psetsockopt
	}
	return -1, psetsockopt
}

func getInterfaceIndex(interfaceName string) (int, error) {
	interfaceList, perror := net.Interfaces()
	if interfaceList != nil {
		for _, item := range interfaceList {
			if item.Name == interfaceName {
				return item.Index, nil
			}
		}
		return -1, errors.New("interface not found")
	}
	return -1, perror
}

func fillLinkLayer(interfaceIndex int) syscall.RawSockaddrLinklayer {
	return syscall.RawSockaddrLinklayer{
		Family:   syscall.AF_PACKET,     // sll_family
		Protocol: syscall.ETH_P_ALL,     // sll_protocol
		Ifindex:  int32(interfaceIndex)} // sll_ifindex
}

func bindSocket(socketDescriptor int, linklayer syscall.RawSockaddrLinklayer) error {
	_, _, perror := syscall.Syscall(syscall.SYS_BIND, uintptr(socketDescriptor),
		uintptr(unsafe.Pointer(&linklayer)), unsafe.Sizeof(linklayer))
	if perror > 0 {
		return errors.New("can not bind socket")
	}
	return nil
}
