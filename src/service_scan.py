import socket
from urllib.parse import urlparse
from http.client import HTTPConnection, HTTPSConnection


def scan(ip: str, open_ports: list):
    print("PORT \t SERVICE")

    ssh_check(ip, open_ports)
    http_check(ip, open_ports)
    https_check(ip, open_ports)


def ssh_check(ip: str, open_ports: list):
    for port in open_ports:
        s = socket.socket()
        s.settimeout(5)
        s.connect((ip, port))

        try:
            banner = s.recv(1024)
            banner = banner.decode("utf-8", errors="ignore")

            if banner[0:3] == "SSH":
                print(f"{port} \t SSH")
                s.close()

            s.close()
        except socket.error:
            pass


def http_check(ip: str, open_ports: list):
    for port in open_ports:
        url = f"http://{ip}:{port}"
        url = urlparse(url)

        try:
            conn = HTTPConnection(url.netloc, timeout=3)
            conn.request("HEAD", url.path)

            if conn.getresponse():
                print(f"{port} \t HTTP")

        except:
            pass


def https_check(ip: str, open_ports: list):
    for port in open_ports:
        url = f"https://{ip}:{port}"
        url = urlparse(url)

        try:
            conn = HTTPSConnection(url.netloc, timeout=3)
            conn.request("HEAD", url.path)

            if conn.getresponse():
                print(f"{port} \t HTTPS")

        except:
            pass
