import socket
import sys
from terminal_colors import print_fail, print_warning
from scapy.all import *


# Selecting the right scan based on the user input
def scan(service_s, ip, ports_str):
    ports = port_parse(ports_str)

    print("PORT \t STATUS")
    match service_s:
        case "c":
            open_ports = tcp_connect_scan(ip, ports)
        case "s":
            open_ports = tcp_syn_scan(ip, ports)
        # case "a":
        #    open_ports = tcp_ack_scan(ip, ports)
        # case "w":
        #    open_ports = tcp_window_scan(ip, ports)
        case "f":
            open_ports = tcp_fin_scan(ip, ports)
        case "n":
            open_ports = tcp_null_scan(ip, ports)
        case "x":
            open_ports = tcp_xmas_scan(ip, ports)
        case "u":
            open_ports = udp_scan(ip, ports)
        case None:
            open_ports = tcp_syn_scan(ip, ports)
        case _:
            print_fail("Cannot find scan type")
            sys.exit()

    return open_ports


# Parsing ports we need to scan from user input
def port_parse(port_str: str):
    ports = []

    # Contiguous port list
    if ":" in port_str:
        p_range = port_str.split(":")
        if (
            p_range[0].isnumeric()
            and p_range[1].isnumeric()
            and p_range[0] <= p_range[1]
            and 0 <= int(p_range[0]) <= 65535
            and 0 <= int(p_range[1]) <= 65535
        ):
            for i in range(int(p_range[0]), int(p_range[1]) + 1):
                ports.append(i)
        else:
            print_fail("Error with input ports")
            sys.exit()

    # Random port list
    elif "," in port_str:
        p_list = port_str.split(",")
        for item in p_list:
            if item.isnumeric() and int(item) >= 0 and int(item) <= 65535:
                ports.append(int(item))
            else:
                print_warning(f"port {item} not valid! Skipping it")

    # Single port
    elif port_str.isnumeric() and int(port_str) >= 0 and int(port_str) <= 65535:
        ports.append(int(port_str))

    # Generic error
    else:
        print_fail("Error with input ports")
        sys.exit()

    return ports


# Send: connect() (TCP with SYN)
# Rec:  TCP with SYN/ACK -> open
#       no response -> closed/filtered
def tcp_connect_scan(ip: str, ports: list):
    open_ports = []

    for port in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(4)

        res = s.connect_ex((ip, port))
        if res == 0:
            print(f"{port} \t open")
            open_ports.append(port)
        else:
            pass
            # print(f"{port} \t closed/filtered")
        s.close()

    return open_ports


# Send: SYN
# Rec:  SYN/ACK -> RST -> open
#       RST -> closed
#       no response/ICMP unreachable -> filtered
def tcp_syn_scan(ip: str, ports: list):
    open_ports = []

    for port in ports:
        packet = IP(dst=ip) / TCP(dport=port, flags="S")
        res = sr1(packet, timeout=5, verbose=0)

        if res is None or (
            res.sprintf("%ICMP.type%") == 3
            and res.sprintf("%ICMP.code%") in [1, 2, 3, 9, 10, 13]
        ):
            print(f"{port} \t filtered")

        else:
            flag_res = res.sprintf("%TCP.flags%")

            if flag_res == "RA":
                pass
                # print(f"{port} \t closed")
            elif flag_res == "SA":
                print(f"{port} \t open")
                open_ports.append(port)

    return open_ports


# Send: ACK
# Res:  no response after tumeout/ICMP unreachable error -> filtered
#       RST -> unfiltered
# def tcp_ack_scan(ip: str, ports: list):
#    open_ports = []
#
#    for port in ports:
#        packet = IP(dst=ip) / TCP(dport=port, flags="A")
#        res = sr1(packet, timeout=5, verbose=0)
#        if res is None or (
#            res.sprintf("%ICMP.type%") == 3
#            and res.sprintf("%ICMP.code%") in [1, 2, 3, 9, 10, 13]
#        ):
#            print(f"{port} \t filtered")
#
#        else:
#            flag_res = res.sprintf("%TCP.flags%")
#
#            if flag_res == "R":
#                print(f"{port} \t unfiltered")
#                open_ports.append(port)
#            else:
#                print(f"{port} \t filtered")
#
#   return open_ports


# Send: ACK
# Res:  RST with non-zero window field -> open
#       RST with zero window field -> closed
#       no response/ICMP unreachable -> filtered
# def tcp_window_scan(ip: str, ports: list):
#    open_ports = []
#
#    for port in ports:
#        packet = IP(dst=ip) / TCP(dport=port, flags="A")
#        res = sr1(packet, timeout=5, verbose=0)
#        if res == None or res.sprintf("%ICMP.type%") == 3:
#            print(f"{port} \t filtered")
#
#        else:
#            flag_res = res.sprintf("%TCP.flags%")
#
#            if flag_res == "R":
#                if res.window > 0:
#                    print(f"{port} \t open")
#                    oprn_ports.append(port)
#                elif res.window == 0:
#                    pass
#                    # print(f"{port} \t closed")
#    return oprn_ports


# Send: FIN bit on
# Rec:  no repsonse: open/filtered
#       TCP RST -> closed
#       ICMP UNREACHABLE -> filtered
def tcp_fin_scan(ip: str, ports: list):
    open_ports = []

    for port in ports:
        packet = IP(dst=ip) / TCP(dport=port, flags="F")
        res = sr1(packet, timeout=5, verbose=0)

        if res is None:
            print(f"{port} \t open/filtered")
            open_ports.append(port)

        else:
            flag_res = res.sprintf("%TCP.flags%")
            icmp_type = res.sprintf("%ICMP.type%")
            icmp_code = res.sprintf("%ICMP.code%")

            if flag_res == "RA":
                pass
                # print(f"{port} \t closed")
            elif icmp_type == 3 and icmp_code in [1, 2, 3, 9, 10, 13]:
                print(f"{port} \t filtered")

    return open_ports


# Send: no bits set
# Rec:  no repsonse: open/filtered
#       TCP RST -> closed
#       ICMP UNREACHABLE -> filtered
def tcp_null_scan(ip: str, ports: list):
    open_ports = []

    for port in ports:
        packet = IP(dst=ip) / TCP(dport=port, flags="")
        res = sr1(packet, timeout=5, verbose=0)

        if res is None:
            print(f"{port} \t open/filtered")
            open_ports.append(port)

        else:
            flag_res = res.sprintf("%TCP.flags%")
            icmp_type = res.sprintf("%ICMP.type%")
            icmp_code = res.sprintf("%ICMP.code%")

            if flag_res == "RA":
                pass
                # print(f"{port} \t closed")
            elif icmp_type == 3 and icmp_code in [1, 2, 3, 9, 10, 13]:
                print(f"{port} \t filtered")

    return open_ports


# Send: FIN PSH URG bits
# Rec:  no repsonse: open/filtered
#       TCP RST -> closed
#       ICMP UNREACHABLE -> filtered
def tcp_xmas_scan(ip: str, ports: list):
    open_ports = []

    for port in ports:
        packet = IP(dst=ip) / TCP(dport=port, flags="FPU")
        res = sr1(packet, timeout=5, verbose=0)

        if res is None:
            print(f"{port} \t open/filtered")
            open_ports.append(port)

        else:
            flag_res = res.sprintf("%TCP.flags%")
            icmp_type = res.sprintf("%ICMP.type%")
            icmp_code = res.sprintf("%ICMP.code%")

            if flag_res == "RA":
                pass
                # print(f"{port} \t closed")
            elif icmp_type == 3 and icmp_code in [1, 2, 3, 9, 10, 13]:
                print(f"{port} \t filtered")

    return open_ports


# Send: UDP with 0 bytes of data
# Rec:  response -> open
#       no response -> open/filtered
#       ICMP port unreachable -> closed
#       other ICMP errors -> filtered
def udp_scan(ip: str, ports: list):
    open_ports = []

    for port in ports:
        packet = IP(dst=ip) / UDP(dport=port) / "Hello"
        res = sr1(packet, timeout=3, verbose=0)

        if res is None:
            res = sr1(packet, timeout=3, verbose=0)
            if res is None:
                print(f"{port} \t open/filtered")

        else:
            icmp_type = res.sprintf("%ICMP.type%")
            icmp_code = res.sprintf("%ICMP.code%")

            if icmp_type in [3, 13]:
                if icmp_code == 3:
                    pass
                    # print(f"{port} \t closed")
                elif icmp_code in [0, 1, 2, 9, 10, 13]:
                    print(f"{port} \t filtered")

            else:
                pass
                # Unusual state, may be open
                # print(f"{port} \t open")

    return open_ports
