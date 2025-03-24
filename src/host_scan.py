import sys
from terminal_colors import print_fail, print_ok, print_warning
from scapy.all import *


# Check if the host is up
def ping_scan(ip: str):
    packet = IP(dst=ip, ttl=20) / ICMP()
    res = sr1(packet, timeout=5, verbose=0)

    if res == None:
        print_fail("Host is down")
        sys.exit()
    else:
        print_ok("Host is up\n")


def arp_scan(ip: str):
    pass


def tcp_syn_scan(ip: str):
    packet = IP(dst=ip) / TCP(dport=80, flags="S")
    res = sr1(packet, timeout=5, verbose=0)

    flag_res = res.sprintf("%TCP.flags%")

    if flag_res == "RA":
        print_fail("Host is down")
        sys.exit()
    elif flag_res == "SA":
        print_ok("Host is up\n")


def tcp_ack_scan(ip: str):
    pass


def udp_scan(ip: str):
    pass


def ip_protocol_scan(ip: str):
    pass
