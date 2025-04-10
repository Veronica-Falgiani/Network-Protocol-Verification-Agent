#!/home/landsend/Documenti/_Mega/Università/Tesi/Network-Protocol-Verification-Agent/myenv/bin/python3

# Imports
from importlib import util
import parser
import host_scan
import port_scan
import protocol_scan
import execute_tests
import write_result

if __name__ == "__main__":
    args = parser.parser()

    host_s = args.host_scan
    port_s = args.port_scan
    ip = args.host
    ports_str = args.ports
    verbose = args.verbose

    # Verify that user input is correct
    host_scan.ip_parse(ip)
    ports_list = port_scan.port_parse(ports_str)

    print("\nVerifying that the host is up: ")
    host_scan.scan(host_s, ip)

    print("\nStarting port scan: ")
    found_ports, ut = port_scan.scan(port_s, ip, ports_list)
    port_scan.print_ports(found_ports)
    open_ports = port_scan.list_open_ports(found_ports)

    print("\nVerifying protocols active on ports: ")
    if ut == "T":
        services = protocol_scan.TCP_scan(ip, open_ports)
    else:
        services = protocol_scan.UDP_scan(ip, open_ports)

    protocol_scan.print_services(services)

    print("\nTesting protocols found: ")
    report = {}
    # report = execute_tests.print_test(services, ip)

    # Write to file results
    # write_result.result(found_ports, services, report)
