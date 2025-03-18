# Imports
import sys
import host_scan
import port_scan

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: ${sys.argv[0]} ip")

    scan = sys.argv[1]
    ip = sys.argv[2]
    ports = sys.argv[3]

    print("Verifying that the host is up: ")
    host_scan.ping_scan(ip)

    print("Starting port scan: ")
    port_scan.scan(scan, ip, ports)
