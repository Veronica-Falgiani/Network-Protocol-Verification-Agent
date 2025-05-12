import socket
import sys
from utils.terminal_colors import print_fail, print_warning, verbose_print
from scapy.all import *


class PortScan:
    def __init__(self, ip: str):
        self.ip = ip
        self.ports = {}
        self.type = ""
        self.open_ports = []

    def __str__(self):
        string = f"{'PORT':<10s} {'STATUS':<15s}\n"

        for key, value in self.ports.items():
            string += f"{str(key):<10s} {value:<15s}\n"

        return string

    def get_open_ports(self):
        for key, value in self.ports.items():
            if value != "closed" or value != "filtered":
                self.open_ports.append(key)

    # Selecting the right scan based on the user input
    def port_scan(self, port_arg: str, ports_list: list, verbose: bool):
        match port_arg:
            case "c":
                self.tcp_connect_scan(ports_list, verbose)
            case "s":
                self.tcp_syn_scan(ports_list, verbose)
            case "f":
                self.tcp_fin_scan(ports_list, verbose)
            case "n":
                self.tcp_null_scan(ports_list, verbose)
            case "x":
                self.tcp_xmas_scan(ports_list, verbose)
            case "u":
                self.udp_scan(ports_list, verbose)
            case None:
                self.tcp_connect_scan(ports_list, verbose)
            case _:
                print_fail("Cannot find scan type")
                sys.exit()

        # Clean line
        print("\033[K", end="\r")

        if len(self.ports) == 0:
            print_fail("No open ports found!")
            sys.exit()

    # Send: connect() (TCP with SYN)
    # Rec:  TCP with SYN/ACK -> open
    #       no response -> closed/filtered
    def tcp_connect_scan(self, ports_list: list, verbose: bool):
        self.type = "TCP"

        for port in ports_list:
            if verbose:
                print("\033[K", end="\r")
                verbose_print(f"Testing {port}")

            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            res = s.connect_ex((self.ip, port))

            # Port open
            if res == 0:
                # print(f"{port} \t open")
                self.ports[port] = "open"

            # Port closed/filtered
            else:
                pass
                # print(f"{port} \t closed/filtered")
                # found_ports[port] = "closed/filtered"

            s.close()

    # Send: SYN
    # Rec:  SYN/ACK -> RST -> open
    #       RST -> closed
    #       no response/ICMP unreachable -> filtered
    def tcp_syn_scan(self, ports_list: list, verbose: bool):
        self.type = "TCP"

        for port in ports_list:
            if verbose:
                print("\033[K", end="\r")
                verbose_print(f"Testing {port}")

            packet = IP(dst=self.ip) / TCP(dport=port, flags="S")
            res = sr1(packet, timeout=3, verbose=0)

            if res is None or (
                res.sprintf("%ICMP.type%") == 3
                and res.sprintf("%ICMP.code%") in [1, 2, 3, 9, 10, 13]
            ):
                # print(f"{port} \t filtered")
                self.ports[port] = "filtered"

            else:
                flag_res = res.sprintf("%TCP.flags%")

                if flag_res == "RA":
                    pass
                    # print(f"{port} \t closed")
                    # found_ports[port] = "closed"
                elif flag_res == "SA":
                    # print(f"{port} \t open")
                    self.ports[port] = "open"

    # Send: FIN bit on
    # Rec:  no repsonse: open/filtered
    #       TCP RST -> closed
    #       ICMP UNREACHABLE -> filtered
    def tcp_fin_scan(self, ports_list: list, verbose: bool):
        self.type = "TCP"

        for port in ports_list:
            if verbose:
                print("\033[K", end="\r")
                verbose_print(f"Testing {port}")

            packet = IP(dst=self.ip) / TCP(dport=port, flags="F")
            res = sr1(packet, timeout=3, verbose=0)

            if res is None:
                # print(f"{port} \t open/filtered")
                self.ports[port] = "open/filtered"

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
                    self.ports[port] = "filtered"

    # Send: no bits set
    # Rec:  no repsonse: open/filtered
    #       TCP RST -> closed
    #       ICMP UNREACHABLE -> filtered
    def tcp_null_scan(self, ports_list: list, verbose: bool):
        self.type = "TCP"

        for port in ports_list:
            if verbose:
                print("\033[K", end="\r")
                verbose_print(f"Testing {port}")

            packet = IP(dst=self.ip) / TCP(dport=port, flags="")
            res = sr1(packet, timeout=3, verbose=0)

            if res is None:
                # print(f"{port} \t open/filtered")
                self.ports[port] = "open/filtered"

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
                    self.ports[port] = "filtered"

    # Send: FIN PSH URG bits
    # Rec:  no repsonse: open/filtered
    #       TCP RST -> closed
    #       ICMP UNREACHABLE -> filtered
    def tcp_xmas_scan(self, ports_list: list, verbose: bool) -> tuple:
        self.type = "TCP"

        for port in ports_list:
            if verbose:
                print("\033[K", end="\r")
                verbose_print(f"Testing {port}")

            packet = IP(dst=self.ip) / TCP(dport=port, flags="FPU")
            res = sr1(packet, timeout=3, verbose=0)

            if res is None:
                # print(f"{port} \t open/filtered")
                self.ports[port] = "open/filtered"

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
                    self.ports[port] = "filtered"

    # Send: UDP with 0 bytes of data
    # Rec:  response -> open
    #       no response -> open/filtered
    #       ICMP port unreachable -> closed
    #       other ICMP errors -> filtered
    def udp_scan(self, ports_list: list, verbose: bool) -> tuple:
        self.type = "UDP"

        for port in ports_list:
            if verbose:
                print("\033[K", end="\r")
                verbose_print(f"Testing {port}")

            packet = IP(dst=self.ip) / UDP(dport=port) / "Hello"
            res = sr1(packet, timeout=3, verbose=0)

            if res is None:
                res = sr1(packet, timeout=3, verbose=0)
                if res is None:
                    # print(f"{port} \t open/filtered")
                    self.ports[port] = "open/filtered"

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
                        self.ports[port] = "filtered"

                else:
                    # Unusual state, may be open
                    # print(f"{port} \t open")
                    self.ports[port] = "open"
