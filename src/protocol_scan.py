import socket
from scapy.all import *
from ssl import SSLError
from urllib.parse import urlparse
from http.client import HTTPConnection, HTTPSConnection
from ftplib import FTP
from smtplib import SMTP, SMTP_SSL
from telnetlib import Telnet
import ssl
import dns.message, dns.query
from poplib import POP3, POP3_SSL, error_proto
from imaplib import IMAP4, IMAP4_SSL
from impacket.smbconnection import SMBConnection, SessionError


def test_scan(ip: str, ports: list) -> dict:
    services = {}

    # Write portocols to test here
    ssh_check(ip, ports, services)
    http_check(ip, ports, services)
    https_check(ip, ports, services)
    ftp_check(ip, ports, services)
    dns_check(ip, ports, services)
    telnet_check(ip, ports, services)

    # pop_check(ip, ports, services)
    # imap_check(ip, ports, services)

    smtp_check(ip, ports, services)
    smb_check(ip, ports, services)

    # dhcp_check(ip, ports, services)
    # rdp_check(ip, ports, services)
    ssltls_check(ip, ports, services)

    undefined(ports, services)

    services = dict(sorted(services.items()))

    return services


def TCP_scan(ip: str, ports: list) -> dict:
    services = {}

    ssh_check(ip, ports, services)
    http_check(ip, ports, services)
    https_check(ip, ports, services)
    ftp_check(ip, ports, services)
    dns_check(ip, ports, services)
    telnet_check(ip, ports, services)

    # pop_check(ip, ports, services)
    # imap_check(ip, ports, services)

    smtp_check(ip, ports, services)
    smb_check(ip, ports, services)

    # dhcp_check(ip, ports, services)
    # rdp_check(ip, ports, services)
    ssltls_check(ip, ports, services)

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
    rem_ports = []

    for port in open_ports:
        s = socket.socket()
        s.settimeout(5)
        s.connect((ip, port))

        try:
            banner = s.recv(1024)
            banner = banner.decode("utf-8", errors="ignore")

            if banner[0:3] == "SSH":
                # print(f"{port} \t SSH")
                rem_ports.append(port)
                services[port] = "SSH"

            s.close()

        except:
            pass

    for port in rem_ports:
        open_ports.remove(port)


def http_check(ip: str, open_ports: list, services: dict):
    rem_ports = []

    for port in open_ports:
        url = f"http://{ip}:{port}"
        url = urlparse(url)

        try:
            conn = HTTPConnection(url.netloc, timeout=3)
            conn.request("HEAD", url.path)

            if conn.getresponse():
                # print(f"{port} \t HTTP")
                rem_ports.append(port)
                services[port] = "HTTP"

        except:
            pass

    for port in rem_ports:
        open_ports.remove(port)


def https_check(ip: str, open_ports: list, services: dict):
    rem_ports = []

    for port in open_ports:
        url = f"https://{ip}:{port}"
        url = urlparse(url)

        try:
            conn = HTTPSConnection(url.netloc, timeout=3)
            conn.request("HEAD", url.path)

            if conn.getresponse():
                # print(f"{port} \t HTTPS")
                rem_ports.append(port)
                services[port] = "HTTPS"

        except:
            pass

    for port in rem_ports:
        open_ports.remove(port)


def ftp_check(ip: str, open_ports: list, services: dict):
    rem_ports = []

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
                rem_ports.append(port)
                services[port] = "FTP"

            s.close()

        except:
            pass

    for port in rem_ports:
        open_ports.remove(port)


def dns_check(ip: str, open_ports: list, services: dict):
    rem_ports = []

    for port in open_ports:
        try:
            query = dns.message.make_query(".", dns.rdatatype.SOA, flags=0)
            dns.query.udp_with_fallback(query, ip, 3, port)
            # print(f"{port} \t DNS")
            rem_ports.append(port)
            services[port] = "DNS"

        except:
            pass

    for port in rem_ports:
        open_ports.remove(port)


def smtp_check(ip: str, open_ports: list, services: dict):
    rem_ports = []

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
                rem_ports.append(port)
                services[port] = "SMTP"

            s.close()

        except:
            pass

    for port in rem_ports:
        open_ports.remove(port)


def telnet_check(ip: str, open_ports: list, services: dict):
    rem_ports = []

    for port in open_ports:
        try:
            telnet = Telnet(ip, port, timeout=3)
            res = telnet.read_until(b"login: ", timeout=3)
            if "login:" in str(res):
                # print(f"{port} \t Telnet")
                rem_ports.append(port)
                services[port] = "telnet"

            telnet.close()

        except:
            pass

    for port in rem_ports:
        open_ports.remove(port)


def pop_check(ip: str, open_ports: list, services: dict):
    rem_ports = []

    for port in open_ports:
        try:
            pop = POP3(ip, port, timeout=6)
            # print(f"{port} \t POP3")
            rem_ports.append(port)
            services[port] = "POP"

        except error_proto:
            print(str(port) + "Error proto")

        except IOError as e:
            print("POP" + str(port) + str(e))
            pass

    for port in rem_ports:
        open_ports.remove(port)


def imap_check(ip: str, open_ports: list, services: dict):
    rem_ports = []

    for port in open_ports:
        try:
            print(port)
            imap = IMAP4(ip, port, timeout=6)
            # print(f"{port} \t IMAP")
            rem_ports.append(port)
            services[port] = "IMAP"

        except:
            pass

    for port in rem_ports:
        open_ports.remove(port)


def dhcp_check(ip: str, open_ports: list, services: dict):
    rem_ports = []

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

    for port in rem_ports:
        open_ports.remove(port)


def smb_check(ip: str, open_ports: list, services: dict):
    rem_ports = []

    for port in open_ports:
        try:
            smb = SMBConnection("WORKGROUP", ip, sess_port=port, timeout=3)
            smb.close()

            # print(f"{port} \t SMB")
            rem_ports.append(port)
            services[port] = "SMB"

            # smb.login("test", "test")
        except:
            pass

    for port in rem_ports:
        open_ports.remove(port)


def ssltls_check(ip: str, open_ports: list, services: dict):
    rem_ports = []

    for port in open_ports:
        try:
            context = ssl.create_default_context()
            sock = socket.create_connection((ip, port), timeout=3)

            ssock = context.wrap_socket(sock, server_hostname=ip)

            ssock.connect((ip, port))
            ssock.close()

            rem_ports.append(port)
            services[port] = "SSL/TLS"

        except TimeoutError:
            pass

        except ConnectionResetError:
            pass

        except ssl.SSLError as e:
            if "WRONG_VERSION_NUMBER" in str(e):
                rem_ports.append(port)
                services[port] = "SSL/TLS"

            # print(port, e)

    for port in rem_ports:
        open_ports.remove(port)


def undefined(open_ports: list, services: dict):
    for port in open_ports:
        # print(f"{port}\t undefined")
        services[port] = "undefined"
