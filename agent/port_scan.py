import socket
import sys
from utils.terminal_colors import print_fail, print_warning, verbose_print
from scapy.all import *


# Selecting the right scan based on the user input
def port_scan(port_s: str, ip: str, ports: list, verbose: bool):
    match port_s:
        case "c":
            found_ports, ut = tcp_connect_scan(ip, ports, verbose)
        case "s":
            found_ports, ut = tcp_syn_scan(ip, ports, verbose)
        case "f":
            found_ports, ut = tcp_fin_scan(ip, ports, verbose)
        case "n":
            found_ports, ut = tcp_null_scan(ip, ports, verbose)
        case "x":
            found_ports, ut = tcp_xmas_scan(ip, ports, verbose)
        case "u":
            found_ports, ut = udp_scan(ip, ports, verbose)
        case None:
            found_ports, ut = tcp_connect_scan(ip, ports, verbose)
        case _:
            print_fail("Cannot find scan type")
            sys.exit()

    # Clean line
    print("\033[K", end="\r")

    if len(found_ports) == 0:
        print_fail("No open ports found!")
        sys.exit()

    return found_ports, ut


# Parsing ports we need to scan from user input
def port_parse(port_str: str) -> list:
    ports = []

    if port_str == "all":
        ports = list(range(0, 65536))

    # Contiguous port list
    elif ":" in port_str:
        p_range = port_str.split(":")

        if (
            p_range[0].isnumeric()
            and p_range[1].isnumeric()
            and int(p_range[0]) <= int(p_range[1])
            and 0 <= int(p_range[0]) <= 65535
            and 0 <= int(p_range[1]) <= 65535
        ):
            for i in range(int(p_range[0]), int(p_range[1]) + 1):
                ports.append(i)
        else:
            print_fail("Ports are not valid!")
            sys.exit()

    # Random port list
    elif "," in port_str:
        p_list = port_str.split(",")
        for item in p_list:
            if item.isnumeric() and int(item) >= 0 and int(item) <= 65535:
                ports.append(int(item))
            else:
                print_warning(f"port {item} not valid! Skipping it")

        if len(ports) == 0:
            print_fail("Ports are not valid!")
            sys.exit()

    # Single port
    elif port_str.isnumeric() and int(port_str) >= 0 and int(port_str) <= 65535:
        ports.append(int(port_str))

    # Generic error
    else:
        print_fail("Ports are not valid!")
        sys.exit()

    return ports


#
def print_ports(ports: dict):
    print("PORT \t STATUS")
    for key, value in ports.items():
        print(f"{key} \t {value}")


# From a dict of all ports returns a list of open ports
def list_open_ports(ports: dict) -> list:
    open_ports = []

    # Creates a list of ports that are open and open/filtered
    for key, value in ports.items():
        if value != "closed" or value != "filtered":
            open_ports.append(key)

    return open_ports


# Send: connect() (TCP with SYN)
# Rec:  TCP with SYN/ACK -> open
#       no response -> closed/filtered
def tcp_connect_scan(ip: str, ports: list, verbose: bool) -> tuple:
    found_ports = {}

    for port in ports:
        if verbose:
            print("\033[K", end="\r")
            verbose_print(f"Testing {port}")

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        res = s.connect_ex((ip, port))

        # Port open
        if res == 0:
            # print(f"{port} \t open")
            found_ports[port] = "open"

        # Port closed/filtered
        else:
            pass
            # print(f"{port} \t closed/filtered")
            # found_ports[port] = "closed/filtered"

        s.close()

    return (found_ports, "T")


# Send: SYN
# Rec:  SYN/ACK -> RST -> open
#       RST -> closed
#       no response/ICMP unreachable -> filtered
def tcp_syn_scan(ip: str, ports: list, verbose: bool) -> tuple:
    found_ports = {}

    for port in ports:
        if verbose:
            print("\033[K", end="\r")
            verbose_print(f"Testing {port}")

        packet = IP(dst=ip) / TCP(dport=port, flags="S")
        res = sr1(packet, timeout=3, verbose=0)

        if res is None or (
            res.sprintf("%ICMP.type%") == 3
            and res.sprintf("%ICMP.code%") in [1, 2, 3, 9, 10, 13]
        ):
            # print(f"{port} \t filtered")
            found_ports[port] = "filtered"

        else:
            flag_res = res.sprintf("%TCP.flags%")

            if flag_res == "RA":
                pass
                # print(f"{port} \t closed")
                # found_ports[port] = "closed"
            elif flag_res == "SA":
                # print(f"{port} \t open")
                found_ports[port] = "open"

    return (found_ports, "T")


# Send: FIN bit on
# Rec:  no repsonse: open/filtered
#       TCP RST -> closed
#       ICMP UNREACHABLE -> filtered
def tcp_fin_scan(ip: str, ports: list, verbose: bool) -> tuple:
    found_ports = {}

    for port in ports:
        if verbose:
            print("\033[K", end="\r")
            verbose_print(f"Testing {port}")

        packet = IP(dst=ip) / TCP(dport=port, flags="F")
        res = sr1(packet, timeout=3, verbose=0)

        if res is None:
            # print(f"{port} \t open/filtered")
            found_ports[port] = "open/filtered"

        else:
            flag_res = res.sprintf("%TCP.flags%")
            icmp_type = res.sprintf("%ICMP.type%")
            icmp_code = res.sprintf("%ICMP.code%")

            if flag_res == "RA":
                pass
                # print(f"{port} \t closed")
                # found_ports[port] = "closed"
            elif icmp_type == 3 and icmp_code in [1, 2, 3, 9, 10, 13]:
                # print(f"{port} \t filtered")
                found_ports[port] = "filtered"

    return (found_ports, "T")


# Send: no bits set
# Rec:  no repsonse: open/filtered
#       TCP RST -> closed
#       ICMP UNREACHABLE -> filtered
def tcp_null_scan(ip: str, ports: list, verbose: bool) -> tuple:
    found_ports = {}

    for port in ports:
        if verbose:
            print("\033[K", end="\r")
            verbose_print(f"Testing {port}")

        packet = IP(dst=ip) / TCP(dport=port, flags="")
        res = sr1(packet, timeout=3, verbose=0)

        if res is None:
            # print(f"{port} \t open/filtered")
            found_ports[port] = "open/filtered"

        else:
            flag_res = res.sprintf("%TCP.flags%")
            icmp_type = res.sprintf("%ICMP.type%")
            icmp_code = res.sprintf("%ICMP.code%")

            if flag_res == "RA":
                pass
                # print(f"{port} \t closed")
                # found_ports[port] = "closed"
            elif icmp_type == 3 and icmp_code in [1, 2, 3, 9, 10, 13]:
                # print(f"{port} \t filtered")
                found_ports[port] = "filtered"

    return (found_ports, "T")


# Send: FIN PSH URG bits
# Rec:  no repsonse: open/filtered
#       TCP RST -> closed
#       ICMP UNREACHABLE -> filtered
def tcp_xmas_scan(ip: str, ports: list, verbose: bool) -> tuple:
    found_ports = {}

    for port in ports:
        if verbose:
            print("\033[K", end="\r")
            verbose_print(f"Testing {port}")

        packet = IP(dst=ip) / TCP(dport=port, flags="FPU")
        res = sr1(packet, timeout=3, verbose=0)

        if res is None:
            # print(f"{port} \t open/filtered")
            found_ports[port] = "open/filtered"

        else:
            flag_res = res.sprintf("%TCP.flags%")
            icmp_type = res.sprintf("%ICMP.type%")
            icmp_code = res.sprintf("%ICMP.code%")

            if flag_res == "RA":
                pass
                # print(f"{port} \t closed")
                # found_ports[port] = "closed"
            elif icmp_type == 3 and icmp_code in [1, 2, 3, 9, 10, 13]:
                # print(f"{port} \t filtered")
                found_ports[port] = "filtered"

    return (found_ports, "T")


# Send: UDP with 0 bytes of data
# Rec:  response -> open
#       no response -> open/filtered
#       ICMP port unreachable -> closed
#       other ICMP errors -> filtered
def udp_scan(ip: str, ports: list, verbose: bool) -> tuple:
    found_ports = {}

    for port in ports:
        if verbose:
            print("\033[K", end="\r")
            verbose_print(f"Testing {port}")

        packet = IP(dst=ip) / UDP(dport=port) / "Hello"
        res = sr1(packet, timeout=3, verbose=0)

        if res is None:
            res = sr1(packet, timeout=3, verbose=0)
            if res is None:
                # print(f"{port} \t open/filtered")
                found_ports[port] = "open/filtered"

        else:
            icmp_type = res.sprintf("%ICMP.type%")
            icmp_code = res.sprintf("%ICMP.code%")

            if icmp_type == "dest-unreach":
                if icmp_code == "port-unreachable":
                    pass
                    # print(f"{port} \t closed")
                    # found_ports[port] = "closed"
                else:
                    # print(f"{port} \t filtered")
                    found_ports[port] = "filtered"

            else:
                # Unusual state, may be open
                # print(f"{port} \t open")
                found_ports[port] = "open"

    return (found_ports, "U")
