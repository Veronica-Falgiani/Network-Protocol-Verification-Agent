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

    print("\nVerifying service active on ports: ")
    services = service_scan.scan(ip, open_ports)
    service_scan.print_services(services)
