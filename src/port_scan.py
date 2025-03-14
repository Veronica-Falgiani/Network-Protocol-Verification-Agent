import socket
from scapy.all import *


def tcp_connect_scan(ip: str, port: int):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(4)
    try:
        s.connect((ip, port))
        s.close()
        print("Port: " + str(port) + " up")
    except socket.error:
        print("Port: " + str(port) + " unreachable")


def tcp_syn_scan(ip: str):
    pass


def syn_ack_scan(ip: str):
    pass


def ack_scan(ip: str):
    pass


def windows_scan(ip: str):
    pass


def fin_scan(ip: str):
    pass


def null_scan(ip: str):
    pass


def xmas_scan(ip: str):
    pass


def fragmentation_scan(ip: str):
    pass
