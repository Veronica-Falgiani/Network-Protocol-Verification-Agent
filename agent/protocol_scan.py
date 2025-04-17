import socket
from utils.terminal_colors import verbose_print
from scapy.all import *
from urllib.parse import urlparse
from http.client import HTTPConnection, HTTPSConnection, BadStatusLine
from ftplib import FTP, FTP_TLS
from smtplib import SMTP, SMTP_SSL
from telnetlib import Telnet
import ssl
import dns.message, dns.query
from poplib import POP3, POP3_SSL
from imaplib import IMAP4, IMAP4_SSL
from impacket.smbconnection import SMBConnection
import hashlib
import struct
import bencodepy
import requests

# Defining self signed certificate for tls/ssl
context = ssl._create_unverified_context(ssl.PROTOCOL_TLS_CLIENT)
context.load_verify_locations("cert/domain.crt")


def test_scan(ip: str, ports: list, verbose: bool) -> dict:
    services = {}

    # Write portocols to test here
    ftps_check(ip, ports, services, verbose)
    smtps_check(ip, ports, services, verbose)

    """
    # All protocols
    ftp_check(ip, ports, services, verbose)
    ssh_check(ip, ports, services, verbose)
    telnet_check(ip, ports, services, verbose)
    smtp_check(ip, ports, services, verbose)
    dns_check(ip, ports, services, verbose)
    http_check(ip, ports, services, verbose)
    pop_check(ip, ports, services, verbose)
    imap_check(ip, ports, services, verbose)
    smb_check(ip, ports, services, verbose)
    gnutella_check(ip, ports, services, verbose)

    # dhcp_check(ip, ports, services)
    # rdp_check(ip, ports, services)

    # SSL protocols
    ftps_check(ip, ports, services, verbose)
    https_check(ip, ports, services, verbose)
    smtps_check(ip, ports, services, verbose)
    pops_check(ip, ports, services, verbose)
    imaps_check(ip, ports, services, verbose)
    ssltls_check(ip, ports, services, verbose)
    """

    undefined(ports, services, verbose)

    print("\033[K", end="\r")

    services = dict(sorted(services.items()))

    return services


def tcp_scan(ip: str, ports: list, verbose: bool) -> dict:
    services = {}

    ftp_check(ip, ports, services, verbose)
    ssh_check(ip, ports, services, verbose)
    telnet_check(ip, ports, services, verbose)
    smtp_check(ip, ports, services, verbose)
    dns_check(ip, ports, services, verbose)
    http_check(ip, ports, services, verbose)
    pop_check(ip, ports, services, verbose)
    imap_check(ip, ports, services, verbose)
    smb_check(ip, ports, services, verbose)

    # dhcp_check(ip, ports, services)
    # rdp_check(ip, ports, services)

    # SSL protocols
    https_check(ip, ports, services, verbose)
    smtps_check(ip, ports, services, verbose)
    pops_check(ip, ports, services, verbose)
    imaps_check(ip, ports, services, verbose)
    ssltls_check(ip, ports, services, verbose)

    undefined(ports, services, verbose)

    # Clearing line for verbose print
    print("\033[K", end="\r")

    services = dict(sorted(services.items()))

    return services


def udp_scan(ip: str, ports: list, verbose: bool) -> dict:
    services = {}

    http_check(ip, ports, services, verbose)
    https_check(ip, ports, services, verbose)
    dns_check(ip, ports, services, verbose)
    dhcp_check(ip, ports, services, verbose)  # Not working
    # imap_check(ip, ports, services)
    undefined(ports, services, verbose)

    # Clean line for verbose print
    print("\033[K", end="\r")

    services = dict(sorted(services.items()))

    return services


# Prints the result of the protocol scan
def print_protocol(services: dict):
    print("PORT \t SERVICE")
    for key, value in services.items():
        print(f"{key} \t {value}")


# --------------------------
# SSH
# --------------------------
def ssh_check(ip: str, open_ports: list, services: dict, verbose: bool):
    rem_ports = []

    for port in open_ports:
        if verbose:
            print("\033[K", end="\r")
            verbose_print(f"Scanning {port} for SSH")

        s = socket.socket()
        s.settimeout(3)
        s.connect((ip, port))

        try:
            # Checks if the banner of the connection contains SSH
            banner = s.recv(1024)
            banner = banner.decode("utf-8", errors="ignore")

            if banner[0:3] == "SSH":
                rem_ports.append(port)
                services[port] = "SSH"

            s.close()

        except Exception:
            pass

    for port in rem_ports:
        open_ports.remove(port)


# --------------------------
# HTTP
# --------------------------
def http_check(ip: str, open_ports: list, services: dict, verbose: bool):
    rem_ports = []

    for port in open_ports:
        if verbose:
            print("\033[K", end="\r")
            verbose_print(f"Scanning {port} for HTTP")

        url = f"http://{ip}:{port}"
        url = urlparse(url)

        try:
            # Tries to establish a connection using HTTP
            conn = HTTPConnection(url.netloc, timeout=3)
            conn.request("HEAD", url.path)
            res = conn.getresponse()

            # Verifies that the response is valid
            if res.status < 400:
                rem_ports.append(port)
                services[port] = "HTTP"

        except Exception:
            pass

    for port in rem_ports:
        open_ports.remove(port)


# --------------------------
# HTTPS
# --------------------------
def https_check(ip: str, open_ports: list, services: dict, verbose: bool):
    rem_ports = []

    for port in open_ports:
        if verbose:
            print("\033[K", end="\r")
            verbose_print(f"Scanning {port} for HTTPS")

        url = f"https://{ip}:{port}"
        url = urlparse(url)

        try:
            conn = HTTPSConnection(url.netloc, timeout=3, context=context)
            conn.request("HEAD", url.path)
            res = conn.getresponse()

            if res.status < 400:
                rem_ports.append(port)
                services[port] = "HTTPS"

        except ssl.SSLError as e:
            if "WRONG_VERSION_NUMBER" in str(e):
                rem_ports.append(port)
                services[port] = "HTTPS"

        except Exception:
            pass

    for port in rem_ports:
        open_ports.remove(port)


# --------------------------
# FTP
# --------------------------
def ftp_check(ip: str, open_ports: list, services: dict, verbose: bool):
    rem_ports = []

    for port in open_ports:
        if verbose:
            print("\033[K", end="\r")
            verbose_print(f"Scanning {port} for FTP")

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
                rem_ports.append(port)
                services[port] = "FTP"

            s.close()

        except Exception as e:
            pass

    for port in rem_ports:
        open_ports.remove(port)


# --------------------------
# FTP/SSL
# --------------------------
def ftps_check(ip: str, open_ports: list, services: dict, verbose: bool):
    rem_ports = []

    for port in open_ports:
        if verbose:
            print("\033[K", end="\r")
            verbose_print(f"Scanning {port} for FTP-SSL")

        try:
            # FTP_SSL not properly working, need to find out why
            # ftps = FTP_TLS()
            # ftps.connect(ip, port, timeout=3)
            # print(port, ftps)
            # ftps.quit()

            # smtp also responds to this, so we need to verify the banner ?
            sock = socket.create_connection((ip, port), timeout=3)
            ssock = context.wrap_socket(sock, server_hostname=ip)

            banner = ssock.recv(2048)
            banner = banner.decode("utf-8", errors="ignore")

            if "FTP" in banner:
                rem_ports.append(port)
                services[port] = "FTP-SSL"

            ssock.close()

        except ssl.SSLError as e:
            if "WRONG_VERSION_NUMBER" in str(e):
                rem_ports.append(port)
                services[port] = "FTP-SSL"

        except Exception as e:
            print(port, e)
            pass

    for port in rem_ports:
        open_ports.remove(port)


# --------------------------
# DNS
# --------------------------
def dns_check(ip: str, open_ports: list, services: dict, verbose: bool):
    rem_ports = []

    for port in open_ports:
        if verbose:
            print("\033[K", end="\r")
            verbose_print(f"Scanning {port} for DNS")

        try:
            query = dns.message.make_query(".", dns.rdatatype.SOA, flags=0)
            dns.query.udp_with_fallback(query, ip, 3, port)
            # print(f"{port} \t DNS")
            rem_ports.append(port)
            services[port] = "DNS"

        except Exception:
            pass

    for port in rem_ports:
        open_ports.remove(port)


# --------------------------
# SMTP
# --------------------------
def smtp_check(ip: str, open_ports: list, services: dict, verbose: bool):
    rem_ports = []

    for port in open_ports:
        if verbose:
            print("\033[K", end="\r")
            verbose_print(f"Scanning {port} for SMTP")

        try:
            smtp = SMTP(ip, port, timeout=3)
            smtp.ehlo()
            smtp.quit()

            # ftp also responds to this, so we need to verify the banner ?
            s = socket.socket()
            s.connect((ip, port))
            banner = s.recv(1024)
            banner = banner.decode("utf-8", errors="ignore")

            if "SMTP" in banner:
                rem_ports.append(port)
                services[port] = "SMTP"

            s.close()

        except Exception:
            pass

    for port in rem_ports:
        open_ports.remove(port)


# --------------------------
# SMTP/SSL
# --------------------------
def smtps_check(ip: str, open_ports: list, services: dict, verbose: bool):
    rem_ports = []

    for port in open_ports:
        if verbose:
            print("\033[K", end="\r")
            verbose_print(f"Scanning {port} for SMTP-SSL")

        try:
            smtps = SMTP_SSL(ip, port, timeout=3, context=context)
            smtps.ehlo()
            smtps.quit()

            # smtp also responds to this, so we need to verify the banner ?
            sock = socket.create_connection((ip, port), timeout=3)
            ssock = context.wrap_socket(sock, server_hostname=ip)

            banner = ssock.recv(2048)
            banner = banner.decode("utf-8", errors="ignore")

            if "SMTP" in banner:
                rem_ports.append(port)
                services[port] = "SMTP-SSL"

            ssock.close()

        except ssl.SSLError as e:
            if "WRONG_VERSION_NUMBER" in str(e):
                rem_ports.append(port)
                services[port] = "SMTP-SSL"

        except Exception:
            pass

    for port in rem_ports:
        open_ports.remove(port)


# --------------------------
# TELNET
# --------------------------
def telnet_check(ip: str, open_ports: list, services: dict, verbose: bool):
    rem_ports = []

    for port in open_ports:
        if verbose:
            print("\033[K", end="\r")
            verbose_print(f"Scanning {port} for TELNET")

        try:
            telnet = Telnet(ip, port, timeout=3)
            res = telnet.read_until(b"login: ", timeout=3)
            if "login:" in str(res):
                # print(f"{port} \t Telnet")
                rem_ports.append(port)
                services[port] = "TELNET"

            telnet.close()

        except Exception:
            pass

    for port in rem_ports:
        open_ports.remove(port)


# --------------------------
# POP
# --------------------------
def pop_check(ip: str, open_ports: list, services: dict, verbose: bool):
    rem_ports = []

    for port in open_ports:
        if verbose:
            print("\033[K", end="\r")
            verbose_print(f"Scanning {port} for POP")

        try:
            pop = POP3(ip, port, timeout=3)
            pop.quit()

            rem_ports.append(port)
            services[port] = "POP"

        except Exception:
            pass

    for port in rem_ports:
        open_ports.remove(port)


# --------------------------
# POP/SSL
# --------------------------
def pops_check(ip: str, open_ports: list, services: dict, verbose: bool):
    rem_ports = []

    for port in open_ports:
        if verbose:
            print("\033[K", end="\r")
            verbose_print(f"Scanning {port} for POP-SSL")

        try:
            pops = POP3_SSL(ip, port, timeout=3, context=context)
            pops.quit()

            rem_ports.append(port)
            services[port] = "POP-SSL"

        except ssl.SSLError as e:
            if "WRONG_VERSION_NUMBER" in str(e):
                rem_ports.append(port)
                services[port] = "POP-SSL"

        except Exception:
            pass

    for port in rem_ports:
        open_ports.remove(port)


# --------------------------
# IMAP
# --------------------------
def imap_check(ip: str, open_ports: list, services: dict, verbose: bool):
    rem_ports = []

    for port in open_ports:
        if verbose:
            print("\033[K", end="\r")
            verbose_print(f"Scanning {port} for IMAP")

        try:
            IMAP4(ip, port, timeout=3)

            rem_ports.append(port)
            services[port] = "IMAP"

        except Exception:
            pass

    for port in rem_ports:
        open_ports.remove(port)


# --------------------------
# IMAP/SSL
# --------------------------
def imaps_check(ip: str, open_ports: list, services: dict, verbose: bool):
    rem_ports = []

    for port in open_ports:
        if verbose:
            print("\033[K", end="\r")
            verbose_print(f"Scanning {port} for IMAP-SSL")

        try:
            IMAP4_SSL(ip, port, timeout=3, ssl_context=context)

            rem_ports.append(port)
            services[port] = "IMAP-SSL"

        except ssl.SSLError as e:
            if "WRONG_VERSION_NUMBER" in str(e):
                rem_ports.append(port)
                services[port] = "IMAP-SSL"

        except Exception:
            pass

    for port in rem_ports:
        open_ports.remove(port)


# --------------------------
# DHCP -TODO
# --------------------------
def dhcp_check(ip: str, open_ports: list, services: dict, verbose: bool):
    rem_ports = []

    for port in open_ports:
        if verbose:
            print("\033[K", end="\r")
            verbose_print(f"Scanning {port} for DHCP")

        discover_dhcp = (
            Ether(dst="ff:ff:ff:ff:ff:ff", src=RandMAC(), type=0x0800)
            / IP(src="0.0.0.0", dst="255.255.255.255")
            / UDP(dport=port, sport=68)
            / BOOTP(op=1, chaddr=RandMAC())
            / DHCP(options=[("message-type", "discover"), ("end")])
        )

        res = srp1(discover_dhcp, timeout=3, verbose=0)
        print(res)
        if res:
            if "DHCP" in res and res[BOOTP].yiaddr == ip:
                print(res[BOOTP].yiaddr, port)
            else:
                print("No DHCP res")

    for port in rem_ports:
        open_ports.remove(port)


# --------------------------
# SMB
# --------------------------
def smb_check(ip: str, open_ports: list, services: dict, verbose: bool):
    rem_ports = []

    for port in open_ports:
        if verbose:
            print("\033[K", end="\r")
            verbose_print(f"Scanning {port} for SMB")

        try:
            smb = SMBConnection("WORKGROUP", ip, sess_port=port, timeout=3)
            smb.close()

            # print(f"{port} \t SMB")
            rem_ports.append(port)
            services[port] = "SMB"

            # smb.login("test", "test")
        except Exception:
            pass

    for port in rem_ports:
        open_ports.remove(port)


# --------------------------
# SSL/TLS - FIX
# --------------------------
def ssltls_check(ip: str, open_ports: list, services: dict, verbose: bool):
    rem_ports = []

    for port in open_ports:
        if verbose:
            print("\033[K", end="\r")
            verbose_print(f"Scanning {port} for SSL-TLS")

        try:
            sock = socket.create_connection((ip, port), timeout=3)
            ssock = context.wrap_socket(sock, server_hostname=ip)

            ssock.close()

            rem_ports.append(port)
            services[port] = "SSL-TLS"

        # except Exception as e:
        # print(port, e)

        except TimeoutError:
            pass

        except ConnectionResetError:
            pass

        except ssl.SSLError as e:
            if "WRONG_VERSION_NUMBER" in str(e):
                rem_ports.append(port)
                services[port] = "SSL-TLS"

    for port in rem_ports:
        open_ports.remove(port)


# --------------------------
# GNUTELLA
# --------------------------
def gnutella_check(ip: str, open_ports: list, services: dict, verbose: bool):
    rem_ports = []

    for port in open_ports:
        if verbose:
            print("\033[K", end="\r")
            verbose_print(f"Scanning {port} for PROTOCOL")

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((ip, port))
            sock.send(b"GET / HTTP/1.0\n\n")
            res = sock.recv(128)

            if "gnutella" in str(res):
                rem_ports.append(port)
                services[port] = "GNUTELLA"

        except Exception:
            pass

    for port in rem_ports:
        open_ports.remove(port)


# --------------------------
# UNDEFINED
# --------------------------
def undefined(open_ports: list, services: dict, verbose: bool):
    for port in open_ports:
        if verbose:
            print("\033[K", end="\r")
            verbose_print(f"Scanning {port} for Undefined")

        # print(f"{port}\t undefined")
        services[port] = "undefined"


# --------------------------
# UNDEFINED
# --------------------------
def check(ip: str, open_ports: list, services: dict, verbose: bool):
    rem_ports = []

    for port in open_ports:
        if verbose:
            print("\033[K", end="\r")
            verbose_print(f"Scanning {port} for PROTOCOL")

        try:
            # Insert code here

            rem_ports.append(port)
            services[port] = "SSL/TLS"

        except Exception:
            pass

    for port in rem_ports:
        open_ports.remove(port)
