import json
import os
import socket
import ssl
from utils.terminal_colors import verbose_print
from agent.results import Results


class ExecuteTests:
    # Defining self signed certificate for tls/ssl
    context = ssl._create_unverified_context(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations("cert/domain.crt")

    def __init__(self, ip, services):
        self.ip = ip
        self.services = services
        self.report = []

    def __str__(self):
        string = f"{'PORT':<10s} {'PROTOCOL':<15s} {'SERVICE':<100s}\n"

        for result in self.report:
            string += str(result) + "\n"

        return string

    def execute_tests(self, verbose: bool):
        for service in self.services:
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
                    tests = test_file["tests"]

                    max_tests = len(tests)
                    i = 1

                    # Create class
                    results = Results(port, prot, service, max_tests)

                    for name, info in tests.items():
                        if verbose:
                            print("\033[K", end="\r")
                            verbose_print(
                                f"Scanning {port} with {prot} - {service} using {name} [{i}/{max_tests}]"
                            )
                            i += 1

                        # Complex ssl/tls test: establishes a connection and then sends a message and compares results
                        if "SSL" in prot:
                            self.test_ssl(name, info, results, self.ip, port, service)

                        # Complex test: sends a message and compares the results
                        elif "recv" in info or "not_recv" in info:
                            self.test(name, info, results, self.ip, port, service)

                        # Simple test: checks if the port is open
                        else:
                            vulns = {}
                            vulns["name"] = name
                            vulns["service"] = service
                            vulns["description"] = info["description"]
                            vulns["severity"] = info["severity"]
                            results.set_vulns(vulns)

                        # Clean line
                        print("\033[K", end="\r")

            except FileNotFoundError:
                results = Results(port, prot, service, 0)

            self.report.append(results)

    def test(
        self, name: str, info: dict, results: Results, ip: str, port: int, service: str
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
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((ip, port))

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
                vulns = {}
                vulns["name"] = name
                vulns["service"] = service
                vulns["description"] = info["description"]
                vulns["severity"] = info["severity"]
                results.set_vulns(vulns)

            sock.close()

        except TimeoutError:
            pass

    def test_ssl(
        self, name: str, info: dict, results: Results, ip: str, port: int, service: str
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
                vulns = {}
                vulns["name"] = name
                vulns["service"] = service
                vulns["description"] = info["description"]
                vulns["severity"] = info["severity"]
                results.set_vulns(vulns)

            ssock.close()

        except TimeoutError:
            pass

        except ConnectionResetError:
            pass
