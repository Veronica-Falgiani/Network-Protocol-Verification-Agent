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
    if ip == "localhost":
        ip = "127.0.0.1"
    ports = args.ports

    print("Verifying that the host is up: ")
    host_scan.scan(host_s, ip)

    print("Starting port scan: ")
    open_ports = port_scan.scan(port_s, ip, ports)

    print("Verifying service active on ports: ")
    service_scan.scan(open_ports)
