// +build linux windows darwin freebsd netbsd openbsd

package main

import (
	"fmt"
	"os"
	"sync/atomic"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcapgo"
)

func (p *packiffer) dumpPacket(packets *gopacket.Packet, w *pcapgo.Writer) {
	w.WritePacket((*packets).Metadata().CaptureInfo, (*packets).Data())
	atomic.AddInt64(&packetCount, 1)
}

func (p *packiffer) dumpPacketWithLimit(packets *gopacket.Packet, w *pcapgo.Writer) {
	w.WritePacket((*packets).Metadata().CaptureInfo, (*packets).Data())
	atomic.AddInt64(&packetCount, 1)
	if packetCount > int64(packetLimit) {
		fmt.Printf("\n%d packets captured on %s", packetLimit, p.interfaceName)
		os.Exit(0)
	}
}