// +build windows

package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"os/exec"
	"time"
)

type ipAddressList []string

var ipList ipAddressList

func (p *packiffer) firewall() {

	f, perr := os.Open(p.File)

	if perr != nil {
		log.Fatal(perr)
	}

	defer f.Close()

	scanner := bufio.NewScanner(f)

	for scanner.Scan() {

		fmt.Println(scanner.Text())
		ipList = append(ipList, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	for i := 0; i < len(ipList); i++ {

		c := exec.Command("netsh", "advfirewall", "firewall", "add", "rule",
			"name="+ipList[i],
			"dir="+"out",
			"action="+"block",
			"remoteip="+ipList[i],
		)

		c.Stdin = os.Stdin
		c.Stdout = os.Stdout
		c.Stderr = os.Stderr

		err := c.Run()

		if err != nil {
			fmt.Printf("%s\n", err.Error())
			os.Exit(1)
		}

	}

	println("Press ctrl + c to delete firewall and terminate program")

	for {
		time.Sleep(time.Second)
	}

}
