import socket
from terminal_colors import verbose_print
from scapy.all import *
from ssl import SSLCertVerificationError, SSLContext, SSLError
from urllib.parse import urlparse
from http.client import HTTPConnection, HTTPSConnection
import requests
from ftplib import FTP
from smtplib import SMTP
from telnetlib import Telnet
import ssl
import dns.message, dns.query
from poplib import POP3, error_proto
from imaplib import IMAP4
from impacket.smbconnection import SMBConnection

# Defining self signed certificate for tls/ssl
context = ssl._create_unverified_context(ssl.PROTOCOL_TLS_CLIENT)
context.load_verify_locations("src/cert/domain.crt")


def test_scan(ip: str, ports: list, verbose: bool) -> dict:
    services = {}

    # Write portocols to test here
    # pop_check(ip, ports, services, verbose)
    # imap_check(ip, ports, services, verbose)
    smb_check(ip, ports, services, verbose)
    http_check(ip, ports, services, verbose)
    https_check(ip, ports, services, verbose)

    smtp_check(ip, ports, services, verbose)
    ssltls_check(ip, ports, services, verbose)

    undefined(ports, services, verbose)

    print("\033[K", end="\r")

    services = dict(sorted(services.items()))

    return services


def TCP_scan(ip: str, ports: list, verbose: bool) -> dict:
    services = {}

    ssh_check(ip, ports, services, verbose)
    http_check(ip, ports, services, verbose)
    https_check(ip, ports, services, verbose)
    ftp_check(ip, ports, services, verbose)
    dns_check(ip, ports, services, verbose)
    telnet_check(ip, ports, services, verbose)

    # pop_check(ip, ports, services)
    # imap_check(ip, ports, services)

    smtp_check(ip, ports, services, verbose)
    smb_check(ip, ports, services, verbose)

    # dhcp_check(ip, ports, services)
    # rdp_check(ip, ports, services)
    ssltls_check(ip, ports, services, verbose)

    undefined(ports, services, verbose)

    undefined(ports, services, verbose)

    print("\033[K", end="\r")

    services = dict(sorted(services.items()))

    return services


def UDP_scan(ip: str, ports: list, verbose: bool) -> dict:
    services = {}

    http_check(ip, ports, services, verbose)
    https_check(ip, ports, services, verbose)
    dns_check(ip, ports, services, verbose)
    dhcp_check(ip, ports, services, verbose)  # Not working
    # pop_check(ip, ports, services)
    # popssl_check(ip, ports, services)
    # imap_check(ip, ports, services)
    # imapssl_check(ip, ports, services)
    smtp_check(ip, ports, services, verbose)
    # smtpssl_check(ip, ports, services)
    undefined(ports, services, verbose)

    # Clean line
    print("\033[K", end="\r")

    services = dict(sorted(services.items()))

    return services


def print_services(services: dict):
    print("PORT \t SERVICE")
    for key, value in services.items():
        print(f"{key} \t {value}")


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


def http_check(ip: str, open_ports: list, services: dict, verbose: bool):
    rem_ports = []

    for port in open_ports:
        if verbose:
            print("\033[K", end="\r")
            verbose_print(f"Scanning {port} for HTTP")

        url = f"http://{ip}:{port}"
        url = urlparse(url)

        try:
            conn = HTTPConnection(url.netloc, timeout=3)
            conn.request("HEAD", url.path)
            res = conn.getresponse()

            if res.status < 400:
                # print(f"{port} \t HTTP")
                rem_ports.append(port)
                services[port] = "HTTP"

        except:
            pass

    for port in rem_ports:
        open_ports.remove(port)


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
                # print(f"{port} \t HTTPS")
                rem_ports.append(port)
                services[port] = "HTTPS"

        except:
            pass

    for port in rem_ports:
        open_ports.remove(port)


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
                # print(f"{port} \t FTP")
                rem_ports.append(port)
                services[port] = "FTP"

            s.close()

        except:
            pass

    for port in rem_ports:
        open_ports.remove(port)


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

        except:
            pass

    for port in rem_ports:
        open_ports.remove(port)


def smtp_check(ip: str, open_ports: list, services: dict, verbose: bool):
    rem_ports = []

    for port in open_ports:
        if verbose:
            print("\033[K", end="\r")
            verbose_print(f"Scanning {port} for SMTP")

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
                # print(f"{port} \t SMTP")
                rem_ports.append(port)
                services[port] = "SMTP"

            s.close()

        except:
            pass

    for port in rem_ports:
        open_ports.remove(port)


def telnet_check(ip: str, open_ports: list, services: dict, verbose: bool):
    rem_ports = []

    for port in open_ports:
        if verbose:
            print("\033[K", end="\r")
            verbose_print(f"Scanning {port} for Telnet")

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


def pop_check(ip: str, open_ports: list, services: dict, verbose: bool):
    rem_ports = []

    for port in open_ports:
        if verbose:
            print("\033[K", end="\r")
            verbose_print(f"Scanning {port} for POP")

        try:
            pop = POP3(ip, port, timeout=3)
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


def imap_check(ip: str, open_ports: list, services: dict, verbose: bool):
    rem_ports = []

    for port in open_ports:
        if verbose:
            print("\033[K", end="\r")
            verbose_print(f"Scanning {port} for IMAP")

        try:
            print(port)
            imap = IMAP4(ip, port, timeout=3)
            # print(f"{port} \t IMAP")
            rem_ports.append(port)
            services[port] = "IMAP"

        except:
            pass

    for port in rem_ports:
        open_ports.remove(port)


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
        except:
            pass

    for port in rem_ports:
        open_ports.remove(port)


def ssltls_check(ip: str, open_ports: list, services: dict, verbose: bool):
    rem_ports = []

    for port in open_ports:
        if verbose:
            print("\033[K", end="\r")
            verbose_print(f"Scanning {port} for SSL/TLS")

        try:
            sock = socket.create_connection((ip, port), timeout=3)

            ssock = context.wrap_socket(sock, server_hostname=ip)

            ssock.connect((ip, port))
            ssock.close()

            rem_ports.append(port)
            services[port] = "SSL/TLS"

        # except Exception as e:
        # print(port, e)

        except TimeoutError:
            pass

        except ConnectionResetError:
            pass

        except ssl.SSLError as e:
            if "WRONG_VERSION_NUMBER" in str(e):
                rem_ports.append(port)
                services[port] = "SSL/TLS"

    for port in rem_ports:
        open_ports.remove(port)


def undefined(open_ports: list, services: dict, verbose: bool):
    for port in open_ports:
        if verbose:
            print("\033[K", end="\r")
            verbose_print(f"Scanning {port} for Undefined")

        # print(f"{port}\t undefined")
        services[port] = "undefined"


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

        except:
            pass

    for port in rem_ports:
        open_ports.remove(port)
