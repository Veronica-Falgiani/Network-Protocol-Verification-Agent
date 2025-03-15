import socket
from scapy.all import *


# Parsing ports we need to scan from user input
def port_parse(port_str: str):
    ports = []

    # Contiguous port list
    if ":" in port_str:
        p_range = port_str.split(":")
        if (
            p_range[0].isnumeric()
            and p_range[1].isnumeric()
            and 0 <= int(p_range[0]) <= 65535
            and 0 <= int(p_range[1]) <= 65535
        ):
            for i in range(int(p_range[0]), int(p_range[1]) + 1):
                ports.append(i)
        else:
            print("Error with input ports")
            # Random port list
    elif "," in port_str:
        p_list = port_str.split(",")
        for item in p_list:
            if item.isnumeric() and int(item) >= 0 and int(item) <= 65535:
                ports.append(int(item))
            else:
                print(f"port {item} not valid! Skipping it")

    # Single port
    elif port_str.isnumeric() and int(port_str) >= 0 and int(port_str) <= 65535:
        ports.append(int(port_str))

    # Generic error
    else:
        print("Error with input ports")
        sys.exit()

    return ports


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
        pass
        # print("Port: " + str(port) + " closed/filtered")


# Send: SYN
# Rec:  SYN/ACK -> RST -> open
#       RST -> closed
#       no response/ICMP unreachable -> filtered
def tcp_syn_scan(ip: str, port: int):
    packet = IP(dst=ip) / TCP(dport=port, flags="S")
    res = sr1(packet, timeout=5, verbose=0)
    flag_res = res.sprintf("%TCP.flags%")

    if flag_res == "RA":
        pass
        # print(f"{port} \t closed")
    elif flag_res == "SA":
        print(f"{port} \t open")
    else:
        print(f"{port} \t filtered")


# Send: ACK
# Res:  no response after tumeout/ICMP unreachable error -> filtered
#       RST -> unfiltered
def tcp_ack_scan(ip: str):
    pass


# Send: ACK
# Res:  RST with non-zero window field -> open
#       RST with zero window field -> closed
#       no response/ICMP unreachable -> filtered
def tcp_window_scan(ip: str):
    pass


# Send: FIN bit on
# # Rec:  no repsonse: open/filtered
#       TCP RST -> closed
#       ICMP UNREACHABLE -> filtered
def tcp_fin_scan(ip: str):
    pass


# Send: no bits set
# Rec:  no repsonse: open/filtered
#       TCP RST -> closed
#       ICMP UNREACHABLE -> filtered
def tcp_null_scan(ip: str):
    pass


# Send: FIN PSH URG bits
# Rec:  no repsonse: open/filtered
#       TCP RST -> closed
#       ICMP UNREACHABLE -> filtered
def tcp_xmas_scan(ip: str):
    pass


# Send: UDP with 0 bytes of data
# Rec:  response -> open
#       no response -> open/filtered
#       ICMP port unreachable -> closed
#       other ICMP errors -> filtered
def udp_scan(ip: str):
    pass
