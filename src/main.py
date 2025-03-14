# Imports
import sys
import host_scan
import port_scan

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print(f"Usage: ${sys.argv[0]} ip")

    ip = sys.argv[1]
    # print(sys.argv[1])

    print("Verifying that the host is up: ")
    host_scan.ping_scan(ip)

    print("Starting port scan: ")
    for port in range(100):
        port_scan.tcp_connect_scan(ip, port)
