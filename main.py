#!/home/landsend/Documenti/_Mega/Università/Tesi/Network-Protocol-Verification-Agent/myenv/bin/python3

# Imports
import os
import sys
from utils.parser import args_parse, ip_parse, port_parse
from utils.terminal_colors import print_ok, print_fail
from agent.host_scan import host_scan
from agent.port_scan import PortScan
from agent.service_scan import ServiceScan
from agent.execute_tests import ExecuteTests
from utils.write_result import write_result

if __name__ == "__main__":
    if "SUDO_UID" not in os.environ:
        print_fail("This program requires sudo privileges")
        sys.exit()

    args = args_parse()

    host_arg = args.host_scan
    port_arg = args.port_scan
    ip = args.host
    ports_str = args.ports
    verbose = args.verbose

    # Verify that user input is correct
    ip_parse(ip)
    ports_list = port_parse(ports_str)

    # Host scan
    print("\nVerifying that the host is up: ")
    if host_scan(host_arg, ip, verbose):
        print_ok("Host is up")
    else:
        print_fail("Host is down")
        sys.exit()

    # Port scan
    print("\nStarting port scan: ")
    port_scan = PortScan(ip)
    port_scan.port_scan(port_arg, ports_list, verbose)
    port_scan.get_open_ports()
    print(port_scan)

    # Protocol - Service scan
    print("Verifying protocols active on ports: ")
    service_scan = ServiceScan(ip)
    if port_scan.type == "TCP":
        service_scan.tcp_scan(port_scan.open_ports, verbose)
    else:
        service_scan.udp_scan(port_scan.open_ports, verbose)
    print(service_scan)

    # Testing all protocols
    print("Asking for credentials:")
    report = ExecuteTests(ip)
    report.execute_tests(service_scan.services, verbose)
    print("\nTesting protocols found: ")
    if verbose:
        print(report)

    # Write to file results
    write_result(report)
