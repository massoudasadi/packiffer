// +build linux

package main

/*
#cgo pkg-config: libnetfilter_queue
#cgo CFLAGS: -Wall -I/usr/include
#cgo LDFLAGS: -L/usr/lib64/

#ifndef _NETFILTER_H
#define _NETFILTER_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>
#include <math.h>
#include <unistd.h>
#include <netinet/in.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/netfilter.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

typedef struct {
    uint verdict;
    uint length;
    unsigned char *data;
} verdictContainer;

extern void go_callback(int id, unsigned char* data, int len, u_int32_t idx, verdictContainer *vc);

static int nf_callback(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *cb_func){
    uint32_t id = -1;
    struct nfqnl_msg_packet_hdr *ph = NULL;
    unsigned char *buffer = NULL;
    int ret = 0;
    u_int32_t idx;
    verdictContainer vc;

    ph = nfq_get_msg_packet_hdr(nfa);
    id = ntohl(ph->packet_id);

    ret = nfq_get_payload(nfa, &buffer);
    idx = (uint32_t)((uintptr_t)cb_func);

    go_callback(id, buffer, ret, idx, &vc);

    return nfq_set_verdict(qh, id, vc.verdict, vc.length, vc.data);
}

static inline struct nfq_q_handle* CreateQueue(struct nfq_handle *h, u_int16_t queue, u_int32_t idx)
{
    return nfq_create_queue(h, queue, &nf_callback, (void*)((uintptr_t)idx));
}

static inline int Run(struct nfq_handle *h, int fd)
{
    char buf[4096] __attribute__ ((aligned));
    int rv;

    int opt = 1;
    setsockopt(fd, SOL_NETLINK, NETLINK_NO_ENOBUFS, &opt, sizeof(int));

    while ((rv = recv(fd, buf, sizeof(buf), 0)) && rv >= 0) {
        nfq_handle_packet(h, buf, rv);
    }

    return errno;
}

#endif
*/
import "C"

import (
	"fmt"
	"os"
	"sync"
	"time"
	"unsafe"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// forked from
// https://github.com/openshift/geard/tree/be0423a67449bc4be1419e03e8bdf459ff0df07e/pkg/go-netfilter-queue
// https://github.com/AkihiroSuda/go-netfilter-queue

/*
   Copyright 2014 Krishna Raman <kraman@gmail.com>
   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at
       http://www.apache.org/licenses/LICENSE-2.0
   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

/*
Go bindings for libnetfilter_queue
This library provides access to packets in the IPTables netfilter queue (NFQUEUE).
The libnetfilter_queue library is part of the http://netfilter.org/projects/libnetfilter_queue/ project.
*/

/*
install libnetfilter-queue-dev:
sudo apt-get install libnetfilter-queue-dev

usage example:

use IPTables to direct all outgoing Ping/ICMP requests to the queue 0:
iptables -A OUTPUT -p icmp -j NFQUEUE --queue-num 0

You can then use go-netfilter-queue to inspect the packets:

package main

import (
        "fmt"
        "os"
)

func main() {
        var err error

        nfq, err := newNFQueue(0, 100, nfDefaultPacketSize)
        if err != nil {
                fmt.Println(err)
                os.Exit(1)
        }
        defer nfq.close()
        packets := nfq.getPackets()

        for true {
                select {
                case p := <-packets:
                        fmt.Println(p.Packet)
                        p.setVerdict(nfAccept)
                }
        }
}

To inject a new or modified packet in the place of the original packet, use:
p.setVerdict(nfAccept, byte_slice)

Instead of:
p.setVerdict(nfAccept)

To undo the IPTables redirect. Run:
iptables -D OUTPUT -p icmp -j NFQUEUE --queue-num 0
*/

type verdict C.uint

type verdictContainerC C.verdictContainer

type verdictContainer struct {
	Verdict verdict
	Packet  []byte
}

type nfPacket struct {
	Packet         gopacket.Packet
	verdictChannel chan verdictContainer
}

func (p *nfPacket) setVerdict(v verdict) {
	p.verdictChannel <- verdictContainer{Verdict: v, Packet: nil}
}

func (p *nfPacket) setRequeueVerdict(newQueueID uint16) {
	v := uint(nfQueue)
	q := (uint(newQueueID) << 16)
	v = v | q
	p.verdictChannel <- verdictContainer{Verdict: verdict(v), Packet: nil}
}

func (p *nfPacket) setVerdictWithPacket(v verdict, packet []byte) {
	p.verdictChannel <- verdictContainer{Verdict: v, Packet: packet}
}

type nfQueueS struct {
	h       *C.struct_nfq_handle
	qh      *C.struct_nfq_q_handle
	fd      C.int
	packets chan nfPacket
	idx     uint32
}

const (
	afInet  = 2
	afInet6 = 10

	nfDrop   verdict = 0
	nfAccept verdict = 1
	nfStolen verdict = 2
	nfQueue  verdict = 3
	nfRepeat verdict = 4
	nfStop   verdict = 5

	nfDefaultPacketSize uint32 = 0xffff

	ipv4version = 0x40
)

var theTable = make(map[uint32]*chan nfPacket, 0)
var theTabeLock sync.RWMutex

func newNFQueue(queueID uint16, maxPacketsInQueue uint32, packetSize uint32) (*nfQueueS, error) {
	var nfq = nfQueueS{}
	var err error
	var ret C.int

	if nfq.h, err = C.nfq_open(); err != nil {
		return nil, fmt.Errorf("error opening NFQueue handle: %v", err)
	}

	if ret, err = C.nfq_unbind_pf(nfq.h, afInet); err != nil || ret < 0 {
		return nil, fmt.Errorf("error unbinding existing NFQ handler from AF_INET protocol family: %v", err)
	}

	if ret, err = C.nfq_unbind_pf(nfq.h, afInet6); err != nil || ret < 0 {
		return nil, fmt.Errorf("error unbinding existing NFQ handler from AF_INET6 protocol family: %v", err)
	}

	if ret, err := C.nfq_bind_pf(nfq.h, afInet); err != nil || ret < 0 {
		return nil, fmt.Errorf("error binding to AF_INET protocol family: %v", err)
	}

	if ret, err := C.nfq_bind_pf(nfq.h, afInet6); err != nil || ret < 0 {
		return nil, fmt.Errorf("error binding to AF_INET6 protocol family: %v", err)
	}

	nfq.packets = make(chan nfPacket)
	nfq.idx = uint32(time.Now().UnixNano())
	theTabeLock.Lock()
	theTable[nfq.idx] = &nfq.packets
	theTabeLock.Unlock()
	if nfq.qh, err = C.CreateQueue(nfq.h, C.u_int16_t(queueID), C.u_int32_t(nfq.idx)); err != nil || nfq.qh == nil {
		C.nfq_close(nfq.h)
		return nil, fmt.Errorf("error binding to queue: %v", err)
	}

	if ret, err = C.nfq_set_queue_maxlen(nfq.qh, C.u_int32_t(maxPacketsInQueue)); err != nil || ret < 0 {
		C.nfq_destroy_queue(nfq.qh)
		C.nfq_close(nfq.h)
		return nil, fmt.Errorf("unable to set max packets in queue: %v", err)
	}

	if C.nfq_set_mode(nfq.qh, C.u_int8_t(2), C.uint(packetSize)) < 0 {
		C.nfq_destroy_queue(nfq.qh)
		C.nfq_close(nfq.h)
		return nil, fmt.Errorf("unable to set packets copy mode: %v", err)
	}

	if nfq.fd, err = C.nfq_fd(nfq.h); err != nil {
		C.nfq_destroy_queue(nfq.qh)
		C.nfq_close(nfq.h)
		return nil, fmt.Errorf("unable to get queue file-descriptor. %v", err)
	}

	go nfq.run()

	return &nfq, nil
}

func (nfq *nfQueueS) close() {
	C.nfq_destroy_queue(nfq.qh)
	C.nfq_close(nfq.h)
	theTabeLock.Lock()
	delete(theTable, nfq.idx)
	theTabeLock.Unlock()
}

func (nfq *nfQueueS) getPackets() <-chan nfPacket {
	return nfq.packets
}

func (nfq *nfQueueS) run() {
	if errno := C.Run(nfq.h, nfq.fd); errno != 0 {
		fmt.Fprintf(os.Stderr, "Terminating, unable to receive packet due to errno=%d\n", errno)
	}
}

//export go_callback
func go_callback(queueID C.int, data *C.uchar, length C.int, idx uint32, vc *verdictContainerC) {
	xdata := C.GoBytes(unsafe.Pointer(data), length)

	var packet gopacket.Packet
	if xdata[0]&0xf0 == ipv4version {
		packet = gopacket.NewPacket(xdata, layers.LayerTypeIPv4, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
	} else {
		packet = gopacket.NewPacket(xdata, layers.LayerTypeIPv6, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
	}

	p := nfPacket{
		verdictChannel: make(chan verdictContainer),
		Packet:         packet,
	}

	theTabeLock.RLock()
	cb, ok := theTable[idx]
	theTabeLock.RUnlock()
	if !ok {
		fmt.Fprintf(os.Stderr, "Dropping, unexpectedly due to bad idx=%d\n", idx)
		(*vc).verdict = C.uint(nfDrop)
		(*vc).data = nil
		(*vc).length = 0
	}
	select {
	case *cb <- p:
		select {
		case v := <-p.verdictChannel:
			if v.Packet == nil {
				(*vc).verdict = C.uint(v.Verdict)
				(*vc).data = nil
				(*vc).length = 0
			} else {
				(*vc).verdict = C.uint(v.Verdict)
				(*vc).data = (*C.uchar)(unsafe.Pointer(&v.Packet[0]))
				(*vc).length = C.uint(len(v.Packet))
			}
		}

	default:
		fmt.Fprintf(os.Stderr, "Dropping, unexpectedly due to no recv, idx=%d\n", idx)
		(*vc).verdict = C.uint(nfDrop)
		(*vc).data = nil
		(*vc).length = 0
	}
}
