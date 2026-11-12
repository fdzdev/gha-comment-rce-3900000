#!/usr/bin/env python3
"""Send owned L2 markers and ARP replies to peer-runner receiver controls."""

import socket
import struct
import sys
import time


raw = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
raw.bind(("eth0", 0))
source_mac = bytes.fromhex(open("/sys/class/net/eth0/address").read().strip().replace(":", ""))
sent = 0
for argument in sys.argv[1:]:
    encoded_mac, target_ip, marker = argument.split(",", 2)
    target_mac = bytes.fromhex(encoded_mac.replace(":", ""))
    marker = marker.encode()
    custom = target_mac + source_mac + bytes.fromhex("88b5") + marker
    arp = (
        target_mac + source_mac + bytes.fromhex("0806")
        + struct.pack("!HHBBH", 1, 0x0800, 6, 4, 2)
        + source_mac + socket.inet_aton("192.168.0.2")
        + target_mac + socket.inet_aton(target_ip) + marker
    )
    for _ in range(4):
        sent += raw.send(custom) + raw.send(arp)
        time.sleep(0.05)
print(f"L2_SEND targets={len(sys.argv)-1} frames={(len(sys.argv)-1)*8} bytes={sent}")
