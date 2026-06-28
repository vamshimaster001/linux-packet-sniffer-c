# Linux Packet Sniffer in C

A high-performance Linux packet sniffer written in C using AF_PACKET raw sockets.

The sniffer captures live Ethernet frames directly from the Linux kernel networking stack and performs protocol parsing, traffic analysis, statistics collection, and multithreaded packet processing.

## Features

- Capture packets using AF_PACKET raw sockets
- Ethernet frame parsing
- IPv4 packet parsing
- TCP packet parsing
- UDP packet parsing
- ICMP packet parsing
- ARP packet detection
- Application protocol detection (HTTP, HTTPS, DNS, DHCP)
- Payload inspection
- Interface binding (SO_BINDTODEVICE)
- Promiscuous mode support
- Packet filtering
- Traffic statistics
- Traffic rate monitoring
- Top talkers analysis
- Flow tracking
- Multithreaded Producer/Consumer packet queue
- Multiple worker threads
- Logging
- Signal handling and graceful cleanup

## Build

```bash
gcc packet_sniffer.c -o packet_sniffer -pthread
```

## Usage

```bash
sudo ./packet_sniffer
```

## Examples

```bash
sudo ./packet_sniffer tcp
sudo ./packet_sniffer udp
sudo ./packet_sniffer icmp
sudo ./packet_sniffer arp
sudo ./packet_sniffer port 53
sudo ./packet_sniffer --stats-interval 5
sudo ./packet_sniffer --payload-size 32
sudo ./packet_sniffer --no-payload
sudo ./packet_sniffer --interface eth0
sudo ./packet_sniffer --promisc
```

## Technologies

- C
- Linux
- POSIX Threads (pthreads)
- AF_PACKET Raw Sockets
- Socket Programming
- Linux Networking

## License

MIT License
