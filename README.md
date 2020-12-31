<img src="./packiffer.png">

# Packiffer
Packiffer is a lightweight cross-platform packet sniffer/analyzer that let you sniff packets live from network interface or offline pcap files. you can also apply filters and set promiscuous mode on interface.

Features:
<p>-display list of network interfaces</p>
<p>-sniff packets live from interface</p>
<p>-set promiscuous mode on interface</p>
<p>-apply filters to packets</p>
<p>-transform selected packets from pcap file to another</p>
<p>-inspect packets in terminal</p>


Modes:
    <p>Sniff: sniff packets live from interface</p>
    <p>Transform: snif packets from offline pcap</p>
    <p>Inspect: inspect & analysis packets from offline pcap files</p>
# Prerequisites For Binary
<p>Libpcap v1.9.1</p>

# Prerequisites For Source
<p>Golang v1.15.2</p>
<p>GoPacket v1.1.18</p>
<p>Libpcap v1.9.1</p>

# How to get Packiffer
Checkout packiffer git repo using git clone
```
git clone https://github.com/massoudasadi/packiffer.git
cd packiffer
```

# Run Packiffer

Sniff mode:
```
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
./packiffer transform <parameters>

("f", "Specify filter query. Default is all")
("in", "Specify input pcap file")
("od", "Specify output directory.Default is packiffer directory")
("of", "Specify output file name.Default is interface name")
("c", "Limit count of packets to sniff. Default is1000")
```

inspect mode:
```
./packiffer inspect <parameters>

("in", "Specify input pcap file")
("f", "Specify filter query. Default is all")
("c", "Limit count of packets to sniff. Default is 1000")
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
./packiffer inspect -in /path/to/file.pcap
```


