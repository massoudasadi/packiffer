// +build linux

package main

import (
	"fmt"
	"syscall"

	"golang.org/x/sys/unix"
)

func createXdpSocket() (int, error) {
	psocket, perror := syscall.Socket(unix.AF_XDP, syscall.SOCK_RAW, 0)
	defer syscall.Close(psocket)
	if perror != nil {
		fmt.Println("Error: " + perror.Error())
		return psocket, perror
	}
	return psocket, perror
}
