# Linux Packet Sniffer in C

High-performance Linux packet sniffer written in C using raw sockets.

This project captures and analyzes live network traffic directly from the Linux kernel networking stack using AF_PACKET raw sockets.

Features:
- Ethernet parsing
- IPv4 parsing
- TCP parsing
- UDP parsing
- ARP parsing
- Payload inspection
- Protocol detection
- Filtering
- Statistics
- Logging
- Signal handling

Build:
gcc packet_sniffer.c -o packet_sniffer

Run:
sudo ./packet_sniffer

Examples:
sudo ./packet_sniffer tcp
sudo ./packet_sniffer udp
sudo ./packet_sniffer port 53
sudo ./packet_sniffer --stats-interval 5

License:
MIT
