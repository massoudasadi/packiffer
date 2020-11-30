<img src="./packiffer.png">

# Packiffer
Packiffer is a lightweight cross-platform packet sniffer that let you sniff packets live from network interface or offline pcap files. you can also apply filters and promiscuous mode on interface.

# Prerequisites For Binary
Libpcap v1.9.1

# Prerequisites For Source
Golang v1.15.2
GoPacket v1.1.18
Libpcap v1.9.1

# How to get Packiffer
Checkout packiffer git repo using git clone
```
git clone https://github.com/massoudasadi/packiffer.git
cd packiffer
go run packiffer.go -i eth0
```

# Run Packiffer
Display list of network interfaces
```
./packiffer -d
```

Sniff Packets on 'eth0' and save packets in 'eth0.pcap' until Ctrl+C pressed 
```
./packiffer -i eth0
```

Sniff Packets on 'eth0' and save packets in 'eth0.pcap' (promiscuous mode) until Ctrl+C pressed
```
./packiffer -i eth0 -p
```

