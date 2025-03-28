import socket
from urllib.parse import urlparse
from http.client import HTTPConnection, HTTPSConnection
from ftplib import FTP
from smtplib import SMTP, SMTPConnectError


def scan(ip: str, open_ports: list):
    print("PORT \t SERVICE")

    ssh_check(ip, open_ports)
    http_check(ip, open_ports)
    https_check(ip, open_ports)
    ftp_check(ip, open_ports)
    dns_check(ip, open_ports)
    smtp_check(ip, open_ports)


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


def ftp_check(ip, open_ports):
    for port in open_ports:
        try:
            ftp = FTP()
            ftp.connect(host=ip, port=port, timeout=3)
            ftp.quit()

            # smtp also responds to this, so we need to verify the banner ?
            s = socket.socket()
            s.connect((ip, port))
            banner = s.recv(1024)
            banner = banner.decode("utf-8", errors="ignore")

            if "FTP" in banner:
                print(f"{port} \t FTP")
                s.close()
            s.close()

        except:
            pass


def dns_check(ip, open_ports):
    for port in open_ports:
        pass


def smtp_check(ip, open_ports):
    for port in open_ports:
        try:
            smtp = SMTP(host=ip, port=port, timeout=3)
            smtp.ehlo()
            smtp.quit()

            # ftp also responds to this, so we need to verify the banner ?
            s = socket.socket()
            s.connect((ip, port))
            banner = s.recv(1024)
            banner = banner.decode("utf-8", errors="ignore")

            if "SMTP" in banner:
                print(f"{port} \t SMTP")
                s.close()
            s.close()
        except:
            pass
