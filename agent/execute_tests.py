import json
import os
import socket
import ssl
import getpass
from utils.terminal_colors import verbose_print
from agent.results import Results


class ExecuteTests:
    # Defining self signed certificate for tls/ssl
    context = ssl._create_unverified_context(ssl.PROTOCOL_TLS_CLIENT)
    context.options &= ~ssl.OP_NO_SSLv3
    context.minimum_version = 768
    context.load_verify_locations("cert/domain.crt")

    def __init__(self, ip):
        self.ip = ip
        self.report = []

    def __str__(self):
        string = f"{'PORT':<10s} {'PROTOCOL':<15s} {'SERVICE':<100s}\n"

        for result in self.report:
            string += str(result) + "\n"

        return string

    def execute_tests(self, services: list, verbose: bool):
        for service in services:
            port = service["port"]
            prot = service["protocol"]
            service = service["service"]

            # Tests the generic protocol
            rel_path = "../tests/" + prot.lower() + "_test.json"
            base_dir = os.path.dirname(__file__)
            path = os.path.join(base_dir, rel_path)

            try:
                with open(path) as file:
                    test_file = json.load(file)
                    misconfigs = test_file["misconfigs"]
                    login = test_file["login"]
                    auth_misconfigs = test_file["auth_misconfigs"]
                    vuln_services = test_file["vuln_services"]

                    max_misconfigs = len(misconfigs)
                    i_mis = 1

                    max_auth_misconfigs = len(auth_misconfigs)
                    i_auth = 1

                    # Asks the user for login info and inserts it into login string
                    if login:
                        print(f"{prot} - {service} username: ", end="")
                        username = input()
                        password = getpass.getpass(f"{prot} - {service} password: ")
                        if username == "" and password == "":
                            login = ""
                        else:
                            login = login.replace("_username_", username)
                            login = login.replace("_password_", password)

                        print(login)

                    # Create class
                    results = Results(
                        port, prot, service, max_misconfigs, max_auth_misconfigs
                    )

                    # Check if the service is vulnerable by checking the banner
                    self.check_banner(service, vuln_services, results)

                    # Start testing for misconfigurations
                    for name, info in misconfigs.items():
                        vuln = {}

                        if verbose:
                            print("\033[K", end="\r")
                            verbose_print(
                                f"Scanning {port} with {prot} - {service} using {name} [{i_mis}/{max_misconfigs}]"
                            )
                            i_mis += 1

                        # Complex ssl/tls test: establishes a connection and then sends a message and compares results
                        if "SSL" in prot:
                            vuln = self.test_ssl(name, info, self.ip, port, service)
                            self.check_ssltls(service, results)

                        # Complex test: sends a message and compares the results
                        elif "recv" in info or "not_recv" in info:
                            vuln = self.test(name, info, self.ip, port, service)

                        # Simple test: checks if the port is open
                        else:
                            vuln["name"] = name
                            vuln["service"] = service
                            vuln["description"] = info["description"]
                            vuln["severity"] = info["severity"]

                        if vuln:
                            results.set_misconfigs(vuln)

                        # Clean line
                        print("\033[K", end="\r")

                    # Start testing for misconfigurations
                    if login:
                        for name, info in auth_misconfigs.items():
                            vuln = {}

                            if verbose:
                                print("\033[K", end="\r")
                                verbose_print(
                                    f"Scanning {port} with {prot} - {service} using {name} [{i_auth}/{max_auth_misconfigs}]"
                                )
                                i_auth += 1

                            # Complex ssl/tls test: establishes a connection and then sends a message and compares results
                            if "SSL" in prot:
                                vuln = self.test_ssl(
                                    name, info, self.ip, port, service, login
                                )
                                self.check_ssltls(service, results)

                            # Complex test: sends a message and compares the results
                            elif "recv" in info or "not_recv" in info:
                                vuln = self.test(
                                    name, info, self.ip, port, service, login
                                )

                            # Simple test: checks if the port is open
                            else:
                                vuln["name"] = name
                                vuln["service"] = service
                                vuln["description"] = info["description"]
                                vuln["severity"] = info["severity"]

                            if vuln:
                                results.set_auth_misconfigs(vuln)

                            # Clean line
                            print("\033[K", end="\r")

            except FileNotFoundError:
                results = Results(port, prot, service, 0)

            self.report.append(results)

    def test(self, name: str, info: dict, ip: str, port: int, service: str, login=""):
        recv = None
        not_recv = None

        send_str = info["send"]
        send_list = send_str.split("~~")

        if "recv" in info:
            recv = info["recv"]
        elif "not_recv" in info:
            not_recv = info["not_recv"]

        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((ip, port))

            if login:
                login_str = login.split("~~")
                for string in login_str:
                    sock.send(string.encode())
                    res = sock.recv(1024)
                    # TODO: VERIFY LOGIN SUCCESSFUL

            # Sends all the commands to the server
            for send in send_list:
                print(send)
                sock.send(send.encode())
                res = sock.recv(1024)
                print(res.decode())

            # Compares the received message to the one in the json
            if (
                recv is not None
                and recv in res.decode()
                or not_recv is not None
                and not_recv not in res.decode()
            ):
                vuln = {}
                vuln["name"] = name
                vuln["service"] = service
                vuln["description"] = info["description"]
                vuln["severity"] = info["severity"]
                return vuln

            sock.close()

        except TimeoutError:
            pass

    def test_ssl(
        self, name: str, info: dict, ip: str, port: int, service: str, login=""
    ):
        recv = None
        not_recv = None

        send_str = info["send"]
        send_list = send_str.split("~~")

        if "recv" in info:
            recv = info["recv"]
        elif "not_recv" in info:
            not_recv = info["not_recv"]

        try:
            sock = socket.create_connection((ip, port), timeout=3)
            ssock = ExecuteTests.context.wrap_socket(sock, server_hostname=ip)

            if login:
                login_str = login.split("~~")
                for string in login_str:
                    sock.send(string.encode())
                    res = sock.recv(1024)
                    # TODO: VERIFY LOGIN SUCCESSFUL

            # Sends all the commands to the server
            for send in send_list:
                # print(send)
                ssock.send(send.encode())
                res = ssock.recv(1024)
                # print(res.decode())

            # Compares the received message to the one in the json
            if (
                recv is not None
                and recv in res.decode()
                or not_recv is not None
                and not_recv not in res.decode()
            ):
                vuln = {}
                vuln["name"] = name
                vuln["service"] = service
                vuln["description"] = info["description"]
                vuln["severity"] = info["severity"]
                return vuln

            ssock.close()

        except TimeoutError:
            pass

        except ConnectionResetError:
            pass

    def check_banner(self, service: str, vuln_services: dict, results: Results):
        for name, versions in vuln_services.items():
            for version, cve in versions.items():
                if name in service and version in service:
                    results.unsafe_ver = True
                    results.unsafe_ver_cve = cve

    def check_tls(self, service: str, results: Results):
        if "TLSv1.3" not in service and "TLSv1.2" not in service:
            results.unsafe_tls = True
