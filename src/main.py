#!/usr/bin/python3

# Imports
import parser
import host_scan
import port_scan
import protocol_scan
import execute_tests
from datetime import datetime

if __name__ == "__main__":
    args = parser.parser()

    host_s = args.host_scan
    port_s = args.port_scan
    ip = args.host
    ports_str = args.ports

    # Verify that user input is correct
    host_scan.ip_parse(ip)
    ports_list = port_scan.port_parse(ports_str)

    print("\nVerifying that the host is up: ")
    host_scan.scan(host_s, ip)

    print("\nStarting port scan: ")
    found_ports = port_scan.scan(port_s, ip, ports_list)
    port_scan.print_ports(found_ports)
    open_ports = port_scan.list_open_ports(found_ports)

    print("\nVerifying protocols active on ports: ")
    services = protocol_scan.scan(ip, open_ports)
    protocol_scan.print_services(services)

    print("\nTesting protocols found: ")
    # execute_tests.test(services)

    # Write to file results
    file_name = "results_" + datetime.today().strftime("%Y-%m-%d_%H:%M:%S") + ".txt"
    with open(file_name, "w") as res_file:
        res_file.write("##### RESULTS #####\n\n")
        res_file.write("PORT \t STATUS \t SERVICE\n")
        res_file.write("----------------------------\n")
        for port, status in found_ports.items():
            res_file.write(f"{str(port)} \t {status} \t {services[port]}\n")
