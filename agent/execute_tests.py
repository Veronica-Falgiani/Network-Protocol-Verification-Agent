import json
import os
import socket
import ssl
import certifi
import getpass
from utils.terminal_colors import verbose_print
from agent.results import Results


class ExecuteTests:
    # Defining self signed certificate for tls/ssl
    context = ssl._create_unverified_context(ssl.PROTOCOL_TLS_CLIENT)
    context.options &= ~ssl.OP_NO_SSLv3
    context.minimum_version = 768
    context.load_verify_locations(certifi.where())

    def __init__(self, ip):
        self.ip = ip
        self.report = []

    def __str__(self):
        string = f"{'PORT':<10s} {'PROTOCOL':<15s} {'SERVICE':<100s}\n"

        for result in self.report:
            string += str(result) + "\n"

        return string

    def execute_tests(self, services: list, verbose: bool):
        # Protocol test
        for service in services:
            port = service["port"]
            prot = service["protocol"]
            service = service["service"]

            # Tests the generic protocol
            base_dir = os.path.dirname(__file__)
            rel_path_prot = "../tests/prot/" + prot.lower() + "_test.json"
            path_prot = os.path.join(base_dir, rel_path_prot)

            try:
                with open(path_prot) as file:
                    test_file = json.load(file)
                    misconfigs = test_file["misconfigs"]
                    login = test_file["login"]
                    auth_misconfigs = test_file["auth_misconfigs"]
                    serv_names = test_file["serv_names"]

                    # Create class
                    results = Results(port, prot, service)

                    prot_max_misconfigs = len(misconfigs)
                    i_mis = 1

                    prot_max_auth_misconfigs = len(auth_misconfigs)
                    i_auth = 1

                    results.add_prot_max(prot_max_misconfigs, prot_max_auth_misconfigs)

                    # Start testing for misconfigurations
                    auth = False
                    self.check_misconfigs(
                        misconfigs,
                        verbose,
                        i_mis,
                        prot_max_misconfigs,
                        port,
                        prot,
                        service,
                        results,
                        auth,
                    )

                    # If auth_misconfigs has tests, asks the user for login info and inserts the correct login messages in a list
                    if auth_misconfigs:
                        login_list = self.try_login(prot, port, service, login)

                        # Start testing for misconfigurations
                        if login_list:
                            results.prot_auth = True
                            auth = True
                            self.check_misconfigs(
                                auth_misconfigs,
                                verbose,
                                i_auth,
                                prot_max_auth_misconfigs,
                                port,
                                prot,
                                service,
                                results,
                                auth,
                                login_list,
                            )

                    # Services test
                    for name in serv_names:
                        if name in service.lower():
                            rel_path_serv = "../tests/serv/" + name + "_test.json"
                            path_prot = os.path.join(base_dir, rel_path_serv)

                            try:
                                with open(path_prot) as file:
                                    test_file = json.load(file)
                                    misconfigs = test_file["misconfigs"]
                                    login = test_file["login"]
                                    auth_misconfigs = test_file["auth_misconfigs"]
                                    vuln_serv_version = test_file["vuln_serv_version"]

                                    # Check if the service is vulnerable by checking the banner
                                    self.check_banner(
                                        service, vuln_serv_version, results
                                    )

                                    serv_max_misconfigs = len(misconfigs)
                                    i_mis = 1

                                    serv_max_auth_misconfigs = len(auth_misconfigs)
                                    i_auth = 1

                                    results.add_serv_max(
                                        serv_max_misconfigs, serv_max_auth_misconfigs
                                    )

                                    # Start testing for misconfigurations
                                    auth = False
                                    self.check_misconfigs(
                                        misconfigs,
                                        verbose,
                                        i_mis,
                                        serv_max_misconfigs,
                                        port,
                                        prot,
                                        service,
                                        results,
                                        auth,
                                    )

                                    # If auth_misconfigs has tests, asks the user for login info and inserts the correct login messages in a list
                                    if auth_misconfigs:
                                        login_list = self.try_login(
                                            prot, port, service, login
                                        )

                                        # Start testing for misconfigurations
                                        if login_list:
                                            results.serv_auth = True
                                            auth = True
                                            self.check_misconfigs(
                                                auth_misconfigs,
                                                verbose,
                                                i_auth,
                                                serv_max_auth_misconfigs,
                                                port,
                                                prot,
                                                service,
                                                results,
                                                auth,
                                                login_list,
                                            )

                            except FileNotFoundError:
                                pass

            except FileNotFoundError:
                results = Results(port, prot, service)

            self.report.append(results)

    def check_misconfigs(
        self,
        misconfigs,
        verbose,
        i_mis,
        max_misconfigs,
        port,
        prot,
        service,
        results,
        auth,
        login_list=[],
    ):
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
                vuln = self.test_ssl(name, info, self.ip, port, service, login_list)
                self.check_ssltls(service, results)

            # Complex test: sends a message and compares the results
            elif "recv" in info or "not_recv" in info:
                vuln = self.test(name, info, self.ip, port, service, login_list)

            # Simple test: checks if the port is open
            else:
                vuln["name"] = name
                vuln["service"] = service
                vuln["description"] = info["description"]
                vuln["severity"] = info["severity"]

            if vuln and auth:
                results.set_auth_misconfigs(vuln)
            elif vuln and not auth:
                results.set_misconfigs(vuln)

            # Clean line
            print("\033[K", end="\r")

    def test(self, name: str, info: dict, ip: str, port: int, service: str, login_list):
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

            for message in login_list:
                sock.send(message.encode())

            # Sends all the commands to the server
            for send in send_list:
                # print(send)
                sock.send(send.encode())
                res = sock.recv(1024)
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

            sock.close()

        except TimeoutError:
            pass

    def test_ssl(
        self, name: str, info: dict, ip: str, port: int, service: str, login_list
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

            for message in login_list:
                sock.send(message.encode())

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

    def check_banner(self, service: str, vuln_serv_version: dict, results: Results):
        for version, cve in vuln_serv_version.items():
            if version in service:
                results.unsafe_ver = True
                results.unsafe_ver_cve = cve

    def check_tls(self, service: str, results: Results):
        if "TLSv1.3" not in service and "TLSv1.2" not in service:
            results.unsafe_tls = True

    def try_login(self, prot, port, service, login) -> list:
        # Asks the user max 3 times for the password
        for i in range(3):
            # Opens SSL socket
            if "SSL" in prot:
                sock = socket.create_connection((self.ip, port), timeout=3)
                sock = ExecuteTests.context.wrap_socket(sock, server_hostname=self.ip)

            # Opens simple socket
            else:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(5)
                sock.connect((self.ip, port))

            # Asks the user for login ingo
            print(f"{prot} - {service} username: ", end="")
            username = input()
            password = getpass.getpass(f"{prot} - {service} password: ")
            if username == "" and password == "":
                login_list = []
                return login_list
            else:
                login_str = login["send_str"].replace("_username_", username)
                login_str = login_str.replace("_password_", password)

            # Sends the login strings to the server
            login_list = login_str.split("~~")
            for message in login_list:
                sock.send(message.encode())
                res = sock.recv(1024)

            # Checks the response of the server
            if login["recv_str"] in res.decode():
                sock.close()
                return login_list
            else:
                sock.close()
                print(f"Failed login {i + 1}/3")

        sock.close()
        login_list = []
        print("Max login failed")
        return login_list
