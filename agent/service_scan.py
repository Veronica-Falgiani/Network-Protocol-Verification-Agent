import socket
from time import sleep
from utils.terminal_colors import verbose_print
from scapy.all import *
from urllib.parse import urlparse
from http.client import HTTPConnection, HTTPSConnection
from ftplib import FTP, FTP_TLS
from smtplib import SMTP, SMTP_SSL
from telnetlib import Telnet
import ssl
import dns.message, dns.query
from poplib import POP3, POP3_SSL
from imaplib import IMAP4, IMAP4_SSL
from impacket.smbconnection import SMBConnection
from operator import itemgetter


# Defining self signed certificate for tls/ssl
context = ssl._create_unverified_context(ssl.PROTOCOL_TLS_CLIENT)
context.load_verify_locations("cert/domain.crt")


def test_scan(ip: str, ports: list, verbose: bool) -> dict:
    services = []

    # Write portocols to test here

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

    undefined(ports, services, verbose)

    print("\033[K", end="\r")

    # Sorts list by port
    services = sorted(services, key=itemgetter("port"))

    return services


def tcp_scan(ip: str, ports: list, verbose: bool) -> dict:
    services = []

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

    undefined(ports, services, verbose)

    # Clearing line for verbose print
    print("\033[K", end="\r")

    # Sorts list by port
    services = sorted(services, key=itemgetter("port"))

    return services


def udp_scan(ip: str, ports: list, verbose: bool) -> dict:
    services = []

    http_check(ip, ports, services, verbose)
    https_check(ip, ports, services, verbose)
    dns_check(ip, ports, services, verbose)
    dhcp_check(ip, ports, services, verbose)  # Not working
    # imap_check(ip, ports, services)
    undefined(ports, services, verbose)

    # Clean line for verbose print
    print("\033[K", end="\r")

    # Sorts list by port
    services = sorted(services, key=itemgetter("port"))

    return services


# Prints the result of the protocol scan
def print_protocol(services: list):
    print("PORT \t PROTOCOL \t SERVICE")
    for service in services:
        print(f"{service['port']} \t {service['protocol']} \t {service['service']}")


# --------------------------
# FTP
# --------------------------
def ftp_check(ip: str, open_ports: list, services: dict, verbose: bool):
    rem_ports = []

    for port in open_ports:
        service = {}

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

                service["port"] = port
                service["protocol"] = "FTP"
                service["service"] = str(banner).strip()[4:]

                services.append(service)

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
        service = {}

        if verbose:
            print("\033[K", end="\r")
            verbose_print(f"Scanning {port} for FTP-SSL")

        try:
            # FTP_SSL not properly working, need to find out why
            ftps = FTP_TLS()
            ftps.connect(ip, port, timeout=3)
            banner = ftps.getwelcome()
            ftps.quit()

            if "FTP" in banner:
                rem_ports.append(port)

                service["port"] = port
                service["protocol"] = "FTP-SSL"
                service["service"] = str(banner).strip()[4:]

                services.append(service)

        except ssl.SSLError as e:
            if "WRONG_VERSION_NUMBER" in str(e):
                rem_ports.append(port)

                service["port"] = port
                service["protocol"] = "FTP-SSL"
                service["service"] = "undefined"

                services.append(service)

        except Exception as e:
            pass

    for port in rem_ports:
        open_ports.remove(port)


# --------------------------
# SSH
# --------------------------
def ssh_check(ip: str, open_ports: list, services: dict, verbose: bool):
    rem_ports = []

    for port in open_ports:
        service = {}

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

                service["port"] = port
                service["protocol"] = "SSH"
                service["service"] = str(banner).strip()

                services.append(service)

            s.close()

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
        service = {}

        if verbose:
            print("\033[K", end="\r")
            verbose_print(f"Scanning {port} for TELNET")

        try:
            telnet = Telnet(ip, port, timeout=3)
            res = telnet.read_until(b"login: ", timeout=3)

            if "login:" in str(res):
                rem_ports.append(port)

                service["port"] = port
                service["protocol"] = "TELNET"
                service["service"] = "undefined"  # No banner found

                services.append(service)

            telnet.close()

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
        service = {}

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
            sleep(1)  # Banner was cut in half so we need ot wait
            banner = s.recv(1024)

            banner = banner.decode("utf-8", errors="ignore")

            if "SMTP" in banner:
                rem_ports.append(port)

                service["port"] = port
                service["protocol"] = "SMTP"
                service["service"] = str(banner).strip()[4:]

                services.append(service)

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
        service = {}

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

            sleep(1)  # Banner was cut in half so we need ot wait
            banner = ssock.recv(2048)
            banner = banner.decode("utf-8", errors="ignore")

            if "SMTP" in banner:
                rem_ports.append(port)

                service["port"] = port
                service["protocol"] = "SMTP-SSL"
                service["service"] = str(banner).strip()[4:]

                services.append(service)

            ssock.close()

        except ssl.SSLError as e:
            if "WRONG_VERSION_NUMBER" in str(e):
                rem_ports.append(port)

                service["port"] = port
                service["protocol"] = "SMTP-SSL"
                service["service"] = "undefined"

                services.append(service)

        except Exception:
            pass

    for port in rem_ports:
        open_ports.remove(port)


# --------------------------
# DNS
# --------------------------
def dns_check(ip: str, open_ports: list, services: dict, verbose: bool):
    rem_ports = []

    for port in open_ports:
        service = {}

        if verbose:
            print("\033[K", end="\r")
            verbose_print(f"Scanning {port} for DNS")

        try:
            query = dns.message.make_query(".", dns.rdatatype.SOA, flags=0)
            dns.query.udp_with_fallback(query, ip, 3, port)

            rem_ports.append(port)

            service["port"] = port
            service["protocol"] = "DNS"
            service["service"] = "undefined"

            services.append(service)

        except Exception:
            pass

    for port in rem_ports:
        open_ports.remove(port)


# --------------------------
# HTTP
# --------------------------
# Browsers block acessing standard ports, so I made a filter in case it tries to connect
# https://neo4j.com/developer/kb/list-of-restricted-ports-in-browsers/
block_ports = [
    1,
    7,
    9,
    11,
    13,
    15,
    17,
    19,
    20,
    21,
    22,
    23,
    25,
    37,
    42,
    43,
    53,
    77,
    79,
    87,
    95,
    101,
    102,
    103,
    104,
    109,
    110,
    111,
    113,
    115,
    117,
    119,
    123,
    135,
    139,
    143,
    179,
    389,
    465,
    512,
    513,
    514,
    515,
    526,
    530,
    531,
    532,
    540,
    556,
    563,
    587,
    601,
    636,
    993,
    995,
    2049,
    3659,
    4045,
    6000,
    6665,
    6666,
    6667,
    6668,
    6669,
]


def http_check(ip: str, open_ports: list, services: dict, verbose: bool):
    rem_ports = []

    # Removing problematic ports
    open_ports = [i for i in open_ports if i not in block_ports]

    for port in open_ports:
        service = {}

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

                service["port"] = port
                service["protocol"] = "HTTP"
                service["service"] = res.headers["server"]

                services.append(service)

        except Exception:
            pass

    for port in rem_ports:
        open_ports.remove(port)


# --------------------------
# HTTPS
# --------------------------
def https_check(ip: str, open_ports: list, services: dict, verbose: bool):
    rem_ports = []

    # Removing problematic ports
    open_ports = [i for i in open_ports if i not in block_ports]

    for port in open_ports:
        service = {}

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

                service["port"] = port
                service["protocol"] = "HTTPS"
                service["service"] = res.headers["server"]

                services.append(service)

        except ssl.SSLError as e:
            if "WRONG_VERSION_NUMBER" in str(e):
                rem_ports.append(port)

                service["port"] = port
                service["protocol"] = "HTTPS"
                service["service"] = "undefined"

                services.append(service)

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
        service = {}

        if verbose:
            print("\033[K", end="\r")
            verbose_print(f"Scanning {port} for POP")

        try:
            pop = POP3(ip, port, timeout=3)
            banner = pop.getwelcome()
            banner = banner.decode("utf-8", errors="ignore")
            pop.quit()

            rem_ports.append(port)

            service["port"] = port
            service["protocol"] = "POP"
            service["service"] = banner.strip()

            services.append(service)

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
        service = {}

        if verbose:
            print("\033[K", end="\r")
            verbose_print(f"Scanning {port} for POP-SSL")

        try:
            pops = POP3_SSL(ip, port, timeout=3, context=context)
            banner = pops.getwelcome()
            banner = banner.decode("utf-8", errors="ignore")
            pops.quit()

            rem_ports.append(port)

            service["port"] = port
            service["protocol"] = "POP-SSL"
            service["service"] = banner.strip()

            services.append(service)

        except ssl.SSLError as e:
            if "WRONG_VERSION_NUMBER" in str(e):
                rem_ports.append(port)

                service["port"] = port
                service["protocol"] = "POP-SSL"
                service["service"] = banner.strip()

                services.append(service)

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
        service = {}

        if verbose:
            print("\033[K", end="\r")
            verbose_print(f"Scanning {port} for IMAP")

        try:
            imap = IMAP4(ip, port, timeout=3)
            banner = imap.PROTOCOL_VERSION
            imap.shutdown()

            rem_ports.append(port)

            service["port"] = port
            service["protocol"] = "IMAP"
            service["service"] = banner

            services.append(service)

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
        service = {}

        if verbose:
            print("\033[K", end="\r")
            verbose_print(f"Scanning {port} for IMAP-SSL")

        try:
            imap = IMAP4_SSL(ip, port, timeout=3, ssl_context=context)
            banner = imap.PROTOCOL_VERSION
            imap.shutdown()

            rem_ports.append(port)

            service["port"] = port
            service["protocol"] = "IMAP-SSL"
            service["service"] = banner

            services.append(service)

        except ssl.SSLError as e:
            if "WRONG_VERSION_NUMBER" in str(e):
                rem_ports.append(port)

                service["port"] = port
                service["protocol"] = "IMAP-SSL"
                service["service"] = banner

                services.append(service)

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
        service = {}

        if verbose:
            print("\033[K", end="\r")
            verbose_print(f"Scanning {port} for SMB")

        try:
            smb = SMBConnection("WORKGROUP", ip, sess_port=port, timeout=3)
            smb.close()

            # s = socket.socket()
            # s.connect((ip, port))
            # s.send(b"")
            # banner = s.recv(1024)
            # banner = banner.decode("utf-8", errors="ignore")
            # print(banner)

            rem_ports.append(port)

            service["port"] = port
            service["protocol"] = "SMB"
            service["service"] = "undefined"

            services.append(service)

        except Exception:
            pass

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
# SSL/TLS - FIX
# --------------------------
def ssltls_check(ip: str, open_ports: list, services: dict, verbose: bool):
    rem_ports = []

    for port in open_ports:
        service = {}

        if verbose:
            print("\033[K", end="\r")
            verbose_print(f"Scanning {port} for SSL-TLS")

        try:
            sock = socket.create_connection((ip, port), timeout=3)
            ssock = context.wrap_socket(sock, server_hostname=ip)

            ssock.close()

            rem_ports.append(port)

            service["port"] = port
            service["protocol"] = "SSL-TLS"
            service["service"] = "undefined"

            services.append(service)

        # except Exception as e:
        # print(port, e)

        except TimeoutError:
            pass

        except ConnectionResetError:
            pass

        except ssl.SSLError as e:
            if "WRONG_VERSION_NUMBER" in str(e):
                rem_ports.append(port)

                service["port"] = port
                service["protocol"] = "SSL-TS"
                service["service"] = "undefined"

                services.append(service)

    for port in rem_ports:
        open_ports.remove(port)


# --------------------------
# UNDEFINED
# --------------------------
def undefined(open_ports: list, services: dict, verbose: bool):
    for port in open_ports:
        service = {}

        if verbose:
            print("\033[K", end="\r")
            verbose_print(f"Scanning {port} for Undefined")

        service["port"] = port
        service["protocol"] = "undefined"
        service["service"] = "undefined"

        services.append(service)


# --------------------------
# TEMPLATE
# --------------------------
def check(ip: str, open_ports: list, services: dict, verbose: bool):
    rem_ports = []
    service = {}

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
