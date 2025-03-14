import socket
from scapy.all import *


# Send: connect() (TCP with SYN)
# Rec:  TCP with SYN/ACK -> open
#       no response -> closed/filtered
def tcp_connect_scan(ip: str, port: int):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(4)
    try:
        s.connect((ip, port))
        s.close()
        print("Port: " + str(port) + " open")
    except socket.error:
        print("Port: " + str(port) + " closed/filtered")


# Send: SYN
# Rec:  SYN/ACK -> RST -> open
#       RST -> closed
#       no response/ICMP unreachable -> filtered
def syn_scan(ip: str):
    pass


# Send: ACK
# Res:  no response after tumeout/ICMP unreachable error -> filtered
#       RST -> unfiltered
def ack_scan(ip: str):
    pass


# Send: ACK
# Res:  RST with non-zero window field -> open
#       RST with zero window field -> closed
#       no response/ICMP unreachable -> filtered
def window_scan(ip: str):
    pass


# Send: FIN bit on
# # Rec:  no repsonse: open/filtered
#       TCP RST -> closed
#       ICMP UNREACHABLE -> filtered
def fin_scan(ip: str):
    pass


# Send: no bits set
# Rec:  no repsonse: open/filtered
#       TCP RST -> closed
#       ICMP UNREACHABLE -> filtered
def null_scan(ip: str):
    pass


# Send: FIN PSH URG bits
# Rec:  no repsonse: open/filtered
#       TCP RST -> closed
#       ICMP UNREACHABLE -> filtered
def xmas_scan(ip: str):
    pass


# Send: UDP with 0 bytes of data
# Rec:  response -> open
#       no response -> open/filtered
#       ICMP port unreachable -> closed
#       other ICMP errors -> filtered
def udp_scan(ip: str):
    pass
