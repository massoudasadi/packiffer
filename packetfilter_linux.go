// +build linux

package main

func (p *packiffer) firewall() {
	p.runBPF()
}
