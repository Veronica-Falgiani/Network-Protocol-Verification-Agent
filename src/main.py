#!/home/landsend/Documenti/_Mega/Università/Tesi/Network-Protocol-Verification-Agent/myenv/bin/python3

# Imports
import os
import sys
import parser
import terminal_colors
import host_scan
import port_scan
import protocol_scan
import execute_tests
import write_result

if __name__ == "__main__":
    if not "SUDO_UID" in os.environ:
        terminal_colors.print_fail("This program requires sudo privileges")
        sys.exit()

    args = parser.parser()

    host_s = args.host_scan
    port_s = args.port_scan
    ip = args.host
    ports_str = args.ports
    verbose = args.verbose

    # Verify that user input is correct
    host_scan.ip_parse(ip)
    ports_list = port_scan.port_parse(ports_str)

    # Host scan
    print("\nVerifying that the host is up: ")
    host_scan.scan(host_s, ip, verbose)

    # Port scan
    print("\nStarting port scan: ")
    found_ports, ut = port_scan.scan(port_s, ip, ports_list, verbose)
    port_scan.print_ports(found_ports)
    open_ports = port_scan.list_open_ports(found_ports)

    # Protocol scan TCP/UDP
    print("\nVerifying protocols active on ports: ")
    if ut == "T":
        services = protocol_scan.test_scan(ip, open_ports, verbose)
    else:
        services = protocol_scan.test_scan(ip, open_ports, verbose)
    protocol_scan.print_services(services)

    # Testing all protocols
    print("\nTesting protocols found: ")
    report = {}
    report = execute_tests.print_test(services, ip)

    # Write to file results
    write_result.result(found_ports, services, report)
