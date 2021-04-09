// +build linux

package main

import (
	"fmt"
	"runtime"
)

func (p *packiffer) firewall() {
	p.runBPF()
}
