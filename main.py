#!/home/landsend/Documenti/_Mega/Università/Tesi/Network-Protocol-Verification-Agent/myenv/bin/python3

# Imports
import os
import sys
from utils.parser import parser
from utils.terminal_colors import print_fail
from agent.host_scan import ip_parse, host_scan
from agent.port_scan import port_parse, port_scan, print_ports, list_open_ports
from agent.protocol_scan import test_scan, tcp_scan, udp_scan, print_protocol
from agent.execute_tests import execute_tests, print_tests
# from utils.write_result import Results

if __name__ == "__main__":
    if "SUDO_UID" not in os.environ:
        print_fail("This program requires sudo privileges")
        sys.exit()

    args = parser()

    host_s = args.host_scan
    port_s = args.port_scan
    ip = args.host
    ports_str = args.ports
    verbose = args.verbose

    # Verify that user input is correct
    ip_parse(ip)
    ports_list = port_parse(ports_str)

    # Host scan
    print("\nVerifying that the host is up: ")
    host_scan(host_s, ip, verbose)

    # Port scan
    print("\nStarting port scan: ")
    found_ports, ut = port_scan(port_s, ip, ports_list, verbose)
    print_ports(found_ports)
    open_ports = list_open_ports(found_ports)

    # Protocol scan TCP/UDP
    print("\nVerifying protocols active on ports: ")
    if ut == "T":
        services = test_scan(ip, open_ports, verbose)
    else:
        services = test_scan(ip, open_ports, verbose)
    print_protocol(services)

    # Testing all protocols
    print("\nTesting protocols found: ")
    report = []
    report = execute_tests(services, ip, verbose)
    print_tests(report)

    # Write to file results
    # result(found_ports, services, report)
