import sys
import socket
from terminal_colors import print_fail, print_ok
from scapy.all import *

SCAN_PORTS = [21, 22, 80, 443]


# Selecting the right scan based on the user input
def scan(host_s, ip):
    ip_parse(ip)

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

    if res_status:
        print_ok("Host is up")
    else:
        print_fail("Host is down")
        sys.exit()


def ip_parse(ip: str):
    if ip == "localhost":
        ip = "127.0.0.1"
    try:
        socket.inet_aton(ip)
    except socket.error:
        print_fail("IP not valid!")
        sys.exit()


# Check if the host is up
def ping_scan(ip: str):
    res_status = False

    packet = IP(dst=ip, ttl=20) / ICMP()
    res = sr1(packet, timeout=5, verbose=0)

    if res is not None:
        res_status = True

    return res_status


def tcp_syn_scan(ip: str):
    res_status = False

    for port in SCAN_PORTS:
        packet = IP(dst=ip) / TCP(dport=port, flags="S")
        res = sr1(packet, timeout=5, verbose=0)

        flag_res = res.sprintf("%TCP.flags%")

        if flag_res == "SA":
            res_status = True

    return res_status


def tcp_ack_scan(ip: str):
    res_status = False

    for port in SCAN_PORTS:
        packet = IP(dst=ip) / TCP(dport=port, flags="A")
        res = sr1(packet, timeout=5, verbose=0)

        flag_res = res.sprintf("%TCP.flags%")

        if flag_res == "R":
            res_status = True

    return res_status


def udp_scan(ip: str):
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
