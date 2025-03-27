# Imports
import parser
import host_scan
import port_scan
import service_scan

if __name__ == "__main__":
    args = parser.parser()

    host_s = args.host_scan
    port_s = args.port_scan
    ip = args.host
    ports = args.ports

    # Verify that user input is correct
    host_scan.ip_parse(ip)
    ports_list = []
    ports_list = port_scan.port_parse(ports)

    print("\nVerifying that the host is up: ")
    host_scan.scan(host_s, ip)

    print("\nStarting port scan: ")
    open_ports = []
    open_ports = port_scan.scan(port_s, ip, ports_list)

    print("\nVerifying service active on ports: ")
    service_scan.scan(ip, open_ports)
