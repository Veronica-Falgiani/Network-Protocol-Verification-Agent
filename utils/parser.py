import argparse
import sys
import socket
import re
from utils.terminal_colors import print_fail, print_warning

# python3 main.py -hs p -ps s 100:200 192.168.0.1


def args_parse():
    parser = argparse.ArgumentParser(
        prog="main.py",
        description="Agent for Advanced Network Protocol Verification. This program needs sudo privilege to run.",
        add_help=False,
        formatter_class=argparse.RawTextHelpFormatter,
    )

    parser.add_argument(
        "-h", "--help", action="help", help="Show this help message and exit"
    )
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Increasse output verbosity"
    )
    parser.add_argument(
        "-hs",
        "--host_scan",
        help="Host scan to execute: [p]ing, [s]yn, [a]ck, [u]dp (ping scan will be used by default)",
    )
    parser.add_argument(
        "-ps",
        "--port_scan",
        help="Port scan to execute: [c]onnect, [s]yn, [f]in, [n]ull, [x]mas, [u]dp (connect scan will be used by default)",
    )
    parser.add_argument(
        "ports",
        help="Single port [x], multiple ports [x,y,z],  port range [x:y] to scan or all ports [all]",
    )
    parser.add_argument("host", help="Host to scan using ipv4 address")

    args = parser.parse_args()

    return args


# Parses ip from user input
def ip_parse(ip: str):
    regex = "^((25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])\\.){3}(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])$"

    if ip == "localhost":
        ip = "127.0.0.1"
    if re.search(regex, ip):
        return
    else:
        print_fail("IP not valid!")
        sys.exit()


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

        ports.sort()

    # Single port
    elif port_str.isnumeric() and int(port_str) >= 0 and int(port_str) <= 65535:
        ports.append(int(port_str))

    # Generic error
    else:
        print_fail("Ports are not valid!")
        sys.exit()

    return ports
