# Imports
import parser
import host_scan
import port_scan

if __name__ == "__main__":
    args = parser.parser()

    host_s = args.host_scan
    service_s = args.service_scan
    ip = args.host
    ports = args.ports

    print("Verifying that the host is up: ")
    host_scan.ping_scan(ip)

    print("Starting port scan: ")
    port_scan.scan(service_s, ip, ports)

    print("Verifying service active on ports: ")
