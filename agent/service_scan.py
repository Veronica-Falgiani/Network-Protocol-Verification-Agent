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
from enum import *


class ServiceScan:
    # Defining self signed certificate for tls/ssl
    context = ssl._create_unverified_context(ssl.PROTOCOL_TLS_CLIENT)
    context.options &= ~ssl.OP_NO_SSLv3
    context.minimum_version = 768
    context.load_verify_locations("cert/domain.crt")

    def __init__(self, ip: str):
        self.ip = ip
        self.services = []

    def __str__(self):
        string = f"{'PORT':<10s} {'PROTOCOL':<15s} {'SERVICE':<100s}\n"

        for service in self.services:
            string += f"{str(service['port']):<10s} {service['protocol']:<15s} {service['service']:<100s}\n"

        return string

    def test_scan(self, open_ports: list, verbose: bool):
        # Write portocols to test here
        self.ftp_check(open_ports, verbose)
        self.ssh_check(open_ports, verbose)
        self.telnet_check(open_ports, verbose)
        self.smtp_check(open_ports, verbose)
        self.dns_check(open_ports, verbose)
        self.http_check(open_ports, verbose)
        self.pop_check(open_ports, verbose)
        self.imap_check(open_ports, verbose)
        self.smb_check(open_ports, verbose)

        # SSL protocols
        self.ftps_check(open_ports, verbose)
        self.https_check(open_ports, verbose)
        self.smtps_check(open_ports, verbose)
        self.pops_check(open_ports, verbose)
        self.imaps_check(open_ports, verbose)
        self.ssltls_check(open_ports, verbose)

        self.undefined(open_ports, verbose)
        print("\033[K", end="\r")

        # Sorts list by port
        self.services = sorted(self.services, key=itemgetter("port"))

    def tcp_scan(self, open_ports: list, verbose: bool):
        self.ftp_check(open_ports, verbose)
        self.ssh_check(open_ports, verbose)
        self.telnet_check(open_ports, verbose)
        self.smtp_check(open_ports, verbose)
        self.dns_check(open_ports, verbose)
        self.http_check(open_ports, verbose)
        self.pop_check(open_ports, verbose)
        self.imap_check(open_ports, verbose)
        self.smb_check(open_ports, verbose)

        # SSL protocols
        self.ftps_check(open_ports, verbose)
        self.https_check(open_ports, verbose)
        self.smtps_check(open_ports, verbose)
        self.pops_check(open_ports, verbose)
        self.imaps_check(open_ports, verbose)
        self.ssltls_check(open_ports, verbose)

        self.undefined(open_ports, verbose)
        print("\033[K", end="\r")

        # Sorts list by port
        self.services = sorted(self.services, key=itemgetter("port"))

    def udp_scan(self, open_ports: list, verbose: bool):
        self.http_check(open_ports, verbose)
        self.https_check(open_ports, verbose)
        self.dns_check(open_ports, verbose)
        self.dhcp_check(open_ports, verbose)  # Not working
        # imap_check(services)
        self.undefined(open_ports, verbose)

        # Clean line for verbose print
        print("\033[K", end="\r")

        # Sorts list by port
        self.services = sorted(self.services, key=itemgetter("port"))

    # --------------------------
    # FTP
    # --------------------------
    def ftp_check(self, open_ports: list, verbose: bool):
        rem_ports = []
        ip = self.ip

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

                    self.services.append(service)

                s.close()

            except Exception as e:
                pass

        for port in rem_ports:
            open_ports.remove(port)

    # --------------------------
    # FTP/SSL
    # --------------------------
    def ftps_check(self, open_ports: list, verbose: bool):
        rem_ports = []
        ip = self.ip

        for port in open_ports:
            service = {}

            if verbose:
                print("\033[K", end="\r")
                verbose_print(f"Scanning {port} for FTP-SSL")

            try:
                # FTP_SSL not properly working, need to find out why
                # ftps = FTP_TLS()
                # ftps.connect(ip, port, timeout=3)
                # banner = ftps.getwelcome()
                # ftps.quit()

                # smtp also responds to this, so we need to verify the banner ?
                sock = socket.create_connection((ip, port), timeout=3)
                ssock = ServiceScan.context.wrap_socket(sock, server_hostname=ip)
                ssl_version = ssock.version()

                sleep(1)  # Banner was cut in half so we need ot wait
                banner = ssock.recv(2048)
                banner = banner.decode("utf-8", errors="ignore")

                if "FTP" in banner:
                    rem_ports.append(port)

                    service["port"] = port
                    service["protocol"] = "FTP-SSL"
                    service["service"] = str(banner).strip()[4:] + " - " + ssl_version

                    self.services.append(service)

                ssock.close()

            except ssl.SSLCertVerificationError as e:
                print(port, e)

            except Exception as e:
                pass

        for port in rem_ports:
            open_ports.remove(port)

    # --------------------------
    # SSH
    # --------------------------
    def ssh_check(self, open_ports: list, verbose: bool):
        rem_ports = []
        ip = self.ip

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

                    self.services.append(service)

                s.close()

            except Exception:
                pass

        for port in rem_ports:
            open_ports.remove(port)

    # --------------------------
    # TELNET
    # --------------------------
    def telnet_check(self, open_ports: list, verbose: bool):
        rem_ports = []
        ip = self.ip

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

                    self.services.append(service)

                telnet.close()

            except Exception:
                pass

        for port in rem_ports:
            open_ports.remove(port)

    # --------------------------
    # SMTP
    # --------------------------
    def smtp_check(self, open_ports: list, verbose: bool):
        rem_ports = []
        ip = self.ip

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

                    self.services.append(service)

                s.close()

            except Exception:
                pass

        for port in rem_ports:
            open_ports.remove(port)

    # --------------------------
    # SMTP/SSL
    # --------------------------
    def smtps_check(self, open_ports: list, verbose: bool):
        rem_ports = []
        ip = self.ip

        for port in open_ports:
            service = {}

            if verbose:
                print("\033[K", end="\r")
                verbose_print(f"Scanning {port} for SMTP-SSL")

            try:
                smtps = SMTP_SSL(ip, port, timeout=3, context=ServiceScan.context)
                smtps.ehlo()
                smtps.quit()

                # smtp also responds to this, so we need to verify the banner ?
                sock = socket.create_connection((ip, port), timeout=3)
                ssock = ServiceScan.context.wrap_socket(sock, server_hostname=ip)
                ssl_version = ssock.version()

                sleep(1)  # Banner was cut in half so we need ot wait
                banner = ssock.recv(2048)
                banner = banner.decode("utf-8", errors="ignore")

                if "SMTP" in banner:
                    rem_ports.append(port)

                    service["port"] = port
                    service["protocol"] = "SMTP-SSL"
                    service["service"] = str(banner).strip()[4:] + " - " + ssl_version

                    self.services.append(service)

                ssock.close()

            except Exception:
                pass

        for port in rem_ports:
            open_ports.remove(port)

    # --------------------------
    # DNS
    # --------------------------
    def dns_check(self, open_ports: list, verbose: bool):
        rem_ports = []
        ip = self.ip

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

                self.services.append(service)

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

    def http_check(self, open_ports: list, verbose: bool):
        rem_ports = []
        ip = self.ip

        # Removing problematic ports
        remaining_ports = [i for i in open_ports if i not in ServiceScan.block_ports]

        for port in remaining_ports:
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

                banner = res.headers["server"]
                if banner is None:
                    banner = "undefined"

                # Verifies that the response is valid
                if res.status < 400:
                    rem_ports.append(port)

                    service["port"] = port
                    service["protocol"] = "HTTP"
                    service["service"] = banner

                    self.services.append(service)

            except Exception:
                pass

        for port in rem_ports:
            open_ports.remove(port)

    # --------------------------
    # HTTPS
    # --------------------------
    def https_check(self, open_ports: list, verbose: bool):
        rem_ports = []
        ip = self.ip

        # Removing problematic ports
        remaining_ports = [i for i in open_ports if i not in ServiceScan.block_ports]

        for port in remaining_ports:
            service = {}

            if verbose:
                print("\033[K", end="\r")
                verbose_print(f"Scanning {port} for HTTPS")

            url = f"https://{ip}:{port}"
            url = urlparse(url)

            try:
                conn = HTTPSConnection(
                    url.netloc, timeout=3, context=ServiceScan.context
                )
                conn.request("HEAD", url.path)
                res = conn.getresponse()

                banner = res.headers["server"]
                if banner is None:
                    banner = "undefined"

                sock = socket.create_connection((ip, port), timeout=3)
                ssock = ServiceScan.context.wrap_socket(sock, server_hostname=ip)
                ssl_version = ssock.version()

                ssock.close()

                if res.status < 400:
                    rem_ports.append(port)

                    service["port"] = port
                    service["protocol"] = "HTTPS"
                    service["service"] = banner + " - " + ssl_version

                    self.services.append(service)

            except Exception:
                pass

        for port in rem_ports:
            open_ports.remove(port)

    # --------------------------
    # POP
    # --------------------------
    def pop_check(self, open_ports: list, verbose: bool):
        rem_ports = []
        ip = self.ip

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

                self.services.append(service)

            except Exception:
                pass

        for port in rem_ports:
            open_ports.remove(port)

    # --------------------------
    # POP/SSL
    # --------------------------
    def pops_check(self, open_ports: list, verbose: bool):
        rem_ports = []
        ip = self.ip

        for port in open_ports:
            service = {}

            if verbose:
                print("\033[K", end="\r")
                verbose_print(f"Scanning {port} for POP-SSL")

            try:
                pops = POP3_SSL(ip, port, timeout=3, context=ServiceScan.context)
                # Socks gets one byte at a time so I had to banner grab this way
                banner = pops.getwelcome()
                banner = banner.decode("utf-8", errors="ignore")
                pops.quit()

                rem_ports.append(port)

                sock = socket.create_connection((ip, port), timeout=3)
                ssock = ServiceScan.context.wrap_socket(sock, server_hostname=ip)
                ssl_version = ssock.version()

                ssock.close()

                service["port"] = port
                service["protocol"] = "POP-SSL"
                service["service"] = banner.strip() + " - " + ssl_version

                self.services.append(service)

            except Exception:
                pass

        for port in rem_ports:
            open_ports.remove(port)

    # --------------------------
    # IMAP
    # --------------------------
    def imap_check(self, open_ports: list, verbose: bool):
        rem_ports = []
        ip = self.ip

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

                self.services.append(service)

            except Exception:
                pass

        for port in rem_ports:
            open_ports.remove(port)

    # --------------------------
    # IMAP/SSL
    # --------------------------
    def imaps_check(self, open_ports: list, verbose: bool):
        rem_ports = []
        ip = self.ip

        for port in open_ports:
            service = {}

            if verbose:
                print("\033[K", end="\r")
                verbose_print(f"Scanning {port} for IMAP-SSL")

            try:
                imap = IMAP4_SSL(ip, port, timeout=3, ssl_context=ServiceScan.context)
                banner = imap.PROTOCOL_VERSION
                imap.shutdown()

                rem_ports.append(port)

                sock = socket.create_connection((ip, port), timeout=3)
                ssock = ServiceScan.context.wrap_socket(sock, server_hostname=ip)
                ssl_version = ssock.version()

                ssock.close()

                service["port"] = port
                service["protocol"] = "IMAP-SSL"
                service["service"] = banner + " - " + ssl_version

                self.services.append(service)

            except Exception:
                pass

        for port in rem_ports:
            open_ports.remove(port)

    # --------------------------
    # SMB
    # --------------------------
    def smb_check(self, open_ports: list, verbose: bool):
        rem_ports = []
        ip = self.ip

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

                self.services.append(service)

            except Exception:
                pass

        for port in rem_ports:
            open_ports.remove(port)

    # --------------------------
    # SSL/TLS
    # --------------------------
    def ssltls_check(self, open_ports: list, verbose: bool):
        rem_ports = []
        ip = self.ip

        for port in open_ports:
            service = {}

            if verbose:
                print("\033[K", end="\r")
                verbose_print(f"Scanning {port} for SSL-TLS")

            try:
                sock = socket.create_connection((ip, port), timeout=3)
                ssock = ServiceScan.context.wrap_socket(sock, server_hostname=ip)

                version = ssock.version()

                ssock.close()

                rem_ports.append(port)

                service["port"] = port
                service["protocol"] = "SSL-TLS"
                service["service"] = version

                self.services.append(service)

            except Exception as e:
                pass

            except TimeoutError:
                pass

            except ConnectionResetError:
                pass

        for port in rem_ports:
            open_ports.remove(port)

    # --------------------------
    # UNDEFINED
    # --------------------------
    def undefined(self, open_ports: list, verbose: bool):
        for port in open_ports:
            service = {}

            if verbose:
                print("\033[K", end="\r")
                verbose_print(f"Scanning {port} for Undefined")

            service["port"] = port
            service["protocol"] = "undefined"
            service["service"] = "undefined"

            self.services.append(service)

    # --------------------------
    # TEMPLATE
    # --------------------------
    def check(self, open_ports: list, verbose: bool):
        rem_ports = []
        service = {}
        ip = self.ip

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
