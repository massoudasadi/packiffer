[![Go Report Card](https://goreportcard.com/badge/github.com/massoudasadi/packiffer)](https://goreportcard.com/report/github.com/massoudasadi/packiffer)

<img src="/assets/packiffer.png">

# Packiffer
Packiffer is a lightweight cross-platform networking toolkit that let you sniff/analyze/inject/filter packets.

<pre>
Features:
    -display list of network interfaces
    -sniff packets live from interface
    -set promiscuous mode on interface
    -apply filters to packets
    -transform selected packets from pcap file to another
    -inspect packets in terminal
    -inject packets into network
    -filter packets with specified destination ip
</pre>

<pre>
Modes:
    Sniff: 
        sniff packets live from interface

    Transform: 
        transform packets from offline pcap

    Inspect: 
        inspect & analysis packets from offline pcap files

    Inject: 
        Inject Raw & Constructed Packets

    Filter:
        Drop or Accept Packets
</pre>

# Prerequisites For Binary
<p>Libpcap v1.9.1</p>
<p>Clang/LLVM (Only on Linux for eBPF XDP packet filtering)</p>
<p>Iptables (Only on Linux for Iptables packet filtering)</p>

# Prerequisites For Source
<p>Golang v1.16</p>
<p>GoPacket v1.1.19</p>
<p>Go eBPF v0.0.0-20210223</p>
<p>Libpcap v1.9.1</p>
<p>Fiber v2.8.0</p>
<p>Clang/LLVM (Only on Linux for eBPF XDP packet filtering)</p>
<p>Iptables (Only on Linux for Iptables packet filtering)</p>

# How to get Packiffer
Checkout packiffer git repo using git clone
```
git clone https://github.com/massoudasadi/packiffer.git
cd packiffer
```

# Run Packiffer

Sniff mode:
```
make build_go 

./packiffer sniff <parameters>

("i", "Specify interface name. Default is eth0")
("p", "Specify promiscuous mode. Default is false")
("f", "Specify filter query. Default is all")
("od", "Specify output directory. Defaultis packiffer directory")
("of", "Specify output file name. Defaultis interface name")
("sl", "Specify Snapshot Lenght. Default is 2014")
("t", "limit sniffing timeout. Default is 30 seconds")
("c", "Limit count of packets to sniff. Default is 1000")
```

transform mode:
```
make build_go 

./packiffer transform <parameters>

("f", "Specify filter query. Default is all")
("in", "Specify input pcap file")
("od", "Specify output directory.Default is packiffer directory")
("of", "Specify output file name.Default is interface name")
("c", "Limit count of packets to sniff. Default is1000")
```

inspect mode:
```
make build_go 

./packiffer inspect <parameters>

("in", "Specify input pcap file")
("f", "Specify filter query. Default is all")
("c", "Limit count of packets to sniff. Default is 1000")
```

inject mode:
```
make build_go 

./packiffer inject <parameters>

("i", "Specify interface name. Default is eth0")
("ir", "Specify Raw Packet Inject. Default is false")
("ic", "Specify Constructed Packet Inject. Default is False")
("f", "Specify Path to packet file. Default is inject.txt")
```

firewall mode:
```
make build_bpf
make build_go 

./packiffer firewall <parameters>

("i", "Specify interface name. Default is eth0")
("f", "Specify Path to firewall file. Default is firewall.txt")
```

default mode:
```
./packiffer <parameters>

("h", "Specify help display. Default is false")
("d", "Specify devices display. Default is false")
```

# Examples
Display list of network interfaces
```
./packiffer -d
```

Sniff packets on 'eth0' and save packets in 'eth0.pcap' (promiscuous mode) until Ctrl+C pressed
```
./packiffer sniff -i eth0 -p
```

transformonly udp packets from 'eth0.pcap' to 'eth0_udp.pcap' until Ctrl+C pressed 
```
./packiffer transform -in /path/to/eth0.pcap -of eth0_udp
```

inspect only tcp packets from pcap file
```
./packiffer inspect -in /path/to/file.pcap -f tcp
```

inject constructed tcp packets from InjectConstructed.json
```
./packiffer inject -i eth0 -ic -f /path/to/file.json
```

filter packets from ips inside firewall.txt
```
./packiffer firewall -i eth0 -f /path/to/file.txt
```
