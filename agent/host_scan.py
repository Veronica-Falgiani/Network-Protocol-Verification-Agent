import sys
import socket
from utils.terminal_colors import print_fail, print_ok, verbose_print
from scapy.all import *

# Ports used for syn and ack scan
SCAN_PORTS = [21, 22, 80, 443]


# Selecting the right scan based on the user input
def host_scan(host_s: str, ip: str, verbose: bool):
    if verbose:
        verbose_print(f"Verifying {ip}")

    match host_s:
        case "p":
            res_status = ping_scan(ip)
        case "s":
            res_status = tcp_syn_scan(ip)
        case "a":
            res_status = tcp_ack_scan(ip)
        case "u":
            res_status = udp_scan(ip)
        case None:
            res_status = ping_scan(ip)
        case _:
            print_fail("Cannot find host scan type")
            sys.exit()

    # Clean line
    print("\033[K", end="\r")

    if res_status:
        print_ok("Host is up")
    else:
        print_fail("Host is down")
        sys.exit()


# --------------------------
# PING
# --------------------------
def ping_scan(ip: str) -> bool:
    res_status = False

    packet = IP(dst=ip, ttl=20) / ICMP()
    res = sr1(packet, timeout=5, verbose=0)

    if res is not None:
        res_status = True

    return res_status


# --------------------------
# TCP SYN
# --------------------------
def tcp_syn_scan(ip: str) -> bool:
    res_status = False

    for port in SCAN_PORTS:
        packet = IP(dst=ip) / TCP(dport=port, flags="S")
        res = sr1(packet, timeout=5, verbose=0)

        flag_res = res.sprintf("%TCP.flags%")

        if flag_res == "SA":
            res_status = True

    return res_status


# --------------------------
# TCP ACK
# --------------------------
def tcp_ack_scan(ip: str) -> bool:
    res_status = False

    for port in SCAN_PORTS:
        packet = IP(dst=ip) / TCP(dport=port, flags="A")
        res = sr1(packet, timeout=5, verbose=0)

        flag_res = res.sprintf("%TCP.flags%")

        if flag_res == "R":
            res_status = True

    return res_status


# --------------------------
# UDP
# --------------------------
def udp_scan(ip: str) -> bool:
    res_status = False

    # Using a probably unused port
    udp_port = 40125

    packet = IP(dst=ip) / UDP(dport=udp_port) / "Hello"
    res = sr1(packet, timeout=5, verbose=0)
    if res is None:
        return res_status

    icmp_type = res.sprintf("%ICMP.type%")
    icmp_code = res.sprintf("%ICMP.code%")

    if icmp_type == "dest-unreach" and icmp_code == "port-unreachable":
        res_status = True

    return res_status
