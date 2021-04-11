// +build linux

package main

func (p *packiffer) firewall() {
	p.runBPF()
	// p.LinuxFirewall = "ipTables"
	// p.ipTables()
}
