from os import error
import socket
from scapy.all import *
from ssl import SSLError
from urllib.parse import urlparse
from http.client import HTTPConnection, HTTPSConnection
from ftplib import FTP
from smtplib import SMTP, SMTP_SSL
from telnetlib import Telnet
import dns.message, dns.query
from poplib import POP3, POP3_SSL, error_proto
from imaplib import IMAP4, IMAP4_SSL


def TCP_scan(ip: str, ports: list) -> dict:
    services = {}

    ssh_check(ip, ports, services)
    http_check(ip, ports, services)
    https_check(ip, ports, services)
    ftp_check(ip, ports, services)
    dns_check(ip, ports, services)
    telnet_check(ip, ports, services)
    # pop_check(ip, ports, services)
    # popssl_check(ip, ports, services)
    # imap_check(ip, ports, services)
    # imapssl_check(ip, ports, services)
    smtp_check(ip, ports, services)
    # smtpssl_check(ip, ports, services)
    undefined(ports, services)

    services = dict(sorted(services.items()))

    return services


def UDP_scan(ip: str, ports: list) -> dict:
    services = {}

    http_check(ip, ports, services)
    https_check(ip, ports, services)
    dns_check(ip, ports, services)
    dhcp_check(ip, ports, services)  # Not working
    # pop_check(ip, ports, services)
    # popssl_check(ip, ports, services)
    # imap_check(ip, ports, services)
    # imapssl_check(ip, ports, services)
    smtp_check(ip, ports, services)
    # smtpssl_check(ip, ports, services)
    undefined(ports, services)

    services = dict(sorted(services.items()))

    return services


def print_services(services: dict):
    print("PORT \t SERVICE")
    for key, value in services.items():
        print(f"{key} \t {value}")


def ssh_check(ip: str, open_ports: list, services: dict):
    # Putting the default port at the start of the list if it's present
    if 22 in open_ports:
        open_ports.remove(22)
        open_ports.insert(0, 22)

    for port in open_ports:
        s = socket.socket()
        s.settimeout(5)
        s.connect((ip, port))

        try:
            banner = s.recv(1024)
            banner = banner.decode("utf-8", errors="ignore")

            if banner[0:3] == "SSH":
                # print(f"{port} \t SSH")
                open_ports.remove(port)
                services[port] = "SSH"

            s.close()

        except:
            pass


def http_check(ip: str, open_ports: list, services: dict):
    # Putting the default port at the start of the list if it's present
    if 80 in open_ports:
        open_ports.remove(80)
        open_ports.insert(0, 80)

    for port in open_ports:
        url = f"http://{ip}:{port}"
        url = urlparse(url)

        try:
            conn = HTTPConnection(url.netloc, timeout=3)
            conn.request("HEAD", url.path)

            if conn.getresponse():
                # print(f"{port} \t HTTP")
                open_ports.remove(port)
                services[port] = "HTTP"

        except:
            pass


def https_check(ip: str, open_ports: list, services: dict):
    # Putting the default port at the start of the list if it's present
    if 443 in open_ports:
        open_ports.remove(443)
        open_ports.insert(0, 443)

    for port in open_ports:
        url = f"https://{ip}:{port}"
        url = urlparse(url)

        try:
            conn = HTTPSConnection(url.netloc, timeout=3)
            conn.request("HEAD", url.path)

            if conn.getresponse():
                # print(f"{port} \t HTTPS")
                open_ports.remove(port)
                services[port] = "HTTPS"

        except:
            pass


def ftp_check(ip: str, open_ports: list, services: dict):
    # Putting the default port at the start of the list if it's present
    if 21 in open_ports:
        open_ports.remove(21)
        open_ports.insert(0, 21)

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
                # print(f"{port} \t FTP")
                open_ports.remove(port)
                services[port] = "FTP"

            s.close()

        except:
            pass


def dns_check(ip: str, open_ports: list, services: dict):
    # Putting the default port at the start of the list if it's present
    if 53 in open_ports:
        open_ports.remove(53)
        open_ports.insert(0, 53)

    for port in open_ports:
        try:
            query = dns.message.make_query(".", dns.rdatatype.SOA, flags=0)
            dns.query.udp_with_fallback(query, ip, 3, port)
            # print(f"{port} \t DNS")
            open_ports.remove(port)
            services[port] = "DNS"

        except:
            pass


def smtp_check(ip: str, open_ports: list, services: dict):
    # Putting the default port at the start of the list if it's present
    if 25 in open_ports:
        open_ports.remove(25)
        open_ports.insert(0, 25)

    for port in open_ports:
        try:
            smtp = SMTP(host=ip, port=port, timeout=6)
            smtp.ehlo()
            smtp.quit()

            # ftp also responds to this, so we need to verify the banner ?
            s = socket.socket()
            s.connect((ip, port))
            banner = s.recv(1024)
            banner = banner.decode("utf-8", errors="ignore")

            if "SMTP" in banner:
                # print(f"{port} \t SMTP")
                open_ports.remove(port)
                services[port] = "SMTP"

            s.close()

        except:
            pass


def smtpssl_check(ip: str, open_ports: list, services: dict):
    for port in open_ports:
        try:
            smtp = SMTP_SSL(host=ip, port=port, timeout=6)
            smtp.ehlo()
            smtp.quit()

            # ftp also responds to this, so we need to verify the banner ?
            s = socket.socket()
            s.connect((ip, port))
            banner = s.recv(1024)
            banner = banner.decode("utf-8", errors="ignore")

            if "SMTP" in banner:
                # print(f"{port} \t SMTPS")
                open_ports.remove(port)
                services[port] = "SMTPS"

            s.close()

        except SSLError:
            print(port, "SSL Error")
            # print(f"{port} \t SMTPS")
            open_ports.remove(port)
            services[port] = "SMTPS"

        except IOError as e:
            print(port, e)
            pass


def telnet_check(ip: str, open_ports: list, services: dict):
    # Putting the default port at the start of the list if it's present
    if 23 in open_ports:
        open_ports.remove(23)
        open_ports.insert(0, 23)

    for port in open_ports:
        try:
            telnet = Telnet(ip, port, timeout=3)
            res = telnet.read_until(b"login: ", timeout=3)
            if "login:" in str(res):
                # print(f"{port} \t Telnet")
                open_ports.remove(port)
                services[port] = "telnet"

            telnet.close()

        except:
            pass


def pop_check(ip: str, open_ports: list, services: dict):
    for port in open_ports:
        try:
            pop = POP3(ip, port, timeout=6)
            # print(f"{port} \t POP3")
            open_ports.remove(port)
            services[port] = "POP"

        except error_proto:
            print(str(port) + "Error proto")

        except IOError as e:
            print("POP" + str(port) + str(e))
            pass


def popssl_check(ip: str, open_ports: list, services: dict):
    for port in open_ports:
        try:
            popssl = POP3_SSL(ip, port, timeout=6)
            # print(f"{port} \t POP3 SSL")
            open_ports.remove(port)
            services[port] = "POP SSL"

        except error_proto:
            pass

        except SSLError:
            # print(f"{port} \t POP3 SSL")
            open_ports.remove(port)
            services[port] = "POP SSL"

        except:
            pass


def imap_check(ip: str, open_ports: list, services: dict):
    for port in open_ports:
        try:
            print(port)
            imap = IMAP4(ip, port, timeout=6)
            # print(f"{port} \t IMAP")
            open_ports.remove(port)
            services[port] = "IMAP"

        except:
            pass


def imapssl_check(ip: str, open_ports: list, services: dict):
    for port in open_ports:
        try:
            print(port)
            imapssl = IMAP4_SSL(ip, port, timeout=6)
            # print(f"{port} \t IMAP SSL")
            open_ports.remove(port)
            services[port] = "IMAP SSL"

        except:
            pass


def dhcp_check(ip: str, open_ports: list, services: dict):
    for port in open_ports:
        discover_dhcp = (
            Ether(dst="ff:ff:ff:ff:ff:ff", src=RandMAC(), type=0x0800)
            / IP(src="0.0.0.0", dst="255.255.255.255")
            / UDP(dport=port, sport=68)
            / BOOTP(op=1, chaddr=RandMAC())
            / DHCP(options=[("message-type", "discover"), ("end")])
        )

        res = srp1(discover_dhcp, timeout=5, verbose=0)
        print(res)
        if res:
            if "DHCP" in res and res[BOOTP].yiaddr == ip:
                print(res[BOOTP].yiaddr, port)
            else:
                print("No DHCP res")


def undefined(open_ports, services: dict):
    for port in open_ports:
        # print(f"{port}\t undefined")
        services[port] = "undefined"
