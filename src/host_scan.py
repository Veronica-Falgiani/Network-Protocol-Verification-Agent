import sys
import terminal_colors
from scapy.all import *


# Check if the host is up
def ping_scan(ip: str):
    packet = IP(dst=ip, ttl=20) / ICMP()
    res = sr1(packet, timeout=5, verbose=0)

    if res == None:
        print(
            terminal_colors.bcolors.WARNING
            + "Host is down"
            + terminal_colors.bcolors.ENDC
        )
        sys.exit()
    else:
        print(
            terminal_colors.bcolors.OKGREEN
            + "Host is up\n"
            + terminal_colors.bcolors.ENDC
        )


def arp_scan(ip: str):
    pass


def tcp_syn_scan(ip: str):
    pass


def tcp_ack_scan(ip: str):
    pass


def udp_scan(ip: str):
    pass


def ip_protocol_scan(ip: str):
    pass
