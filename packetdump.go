// +build linux windows darwin freebsd netbsd openbsd

package main

import (
	"fmt"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcapgo"
)

func (p *packiffer) dumpPacket(packets gopacket.Packet, w *pcapgo.Writer, wg *sync.WaitGroup, mu *sync.Mutex) {
	defer wg.Done()
	mu.Lock()
	if err := w.WritePacket(packets.Metadata().CaptureInfo, packets.Data()); err != nil {
		fmt.Printf("pcap.WritePacket(): " + err.Error())
	}
	mu.Unlock()
}
