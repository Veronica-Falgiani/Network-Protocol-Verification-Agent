import json
import os
import socket
import ssl
from utils.terminal_colors import verbose_print
from agent.results import Results

base_dir = os.path.dirname(__file__)

# Defining self signed certificate for tls/ssl
context = ssl._create_unverified_context(ssl.PROTOCOL_TLS_CLIENT)
context.load_verify_locations("cert/domain.crt")


def execute_tests(services: dict, ip: str, verbose: bool) -> dict:
    report = []

    for port, prot in services.items():
        # Reads from the test files we provide
        rel_path = "../tests/" + prot.lower() + "_test.json"
        path = os.path.join(base_dir, rel_path)

        try:
            with open(path) as file:
                test_file = json.load(file)
                tests = test_file["tests"]

                max_tests = len(tests)
                i = 1

                # Create class
                results = Results(port, prot, None, max_tests)

                for name, info in tests.items():
                    if verbose:
                        print("\033[K", end="\r")
                        verbose_print(
                            f"Scanning {port} with {prot} using {name} [{i}/{max_tests}]"
                        )
                        i += 1

                    # Complex ssl/tls test: establishes a connection and then sends a message and compares results
                    if "SSL" in prot:
                        test_ssl(name, info, results, ip, port)

                    # Complex test: sends a message and compares the results
                    elif "recv" in info:
                        test(name, info, results, ip, port)

                    # Simple test: checks if the port is open
                    else:
                        vulns = {}
                        vulns["name"] = name
                        vulns["description"] = info["description"]
                        vulns["severity"] = info["severity"]
                        results.set_vulns(vulns)

                    # Clean line
                    print("\033[K", end="\r")

                report.append(results)

        except FileNotFoundError:
            results = Results(port, prot, None, 0)
            report.append(results)

    return report


def test(name: str, info: dict, results: Results, ip: str, port: int):
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
            and not_recv in res.decode()
        ):
            vulns = {}
            vulns["name"] = name
            vulns["description"] = info["description"]
            vulns["severity"] = info["severity"]
            results.set_vulns(vulns)

        sock.close()

    except TimeoutError:
        pass


def test_ssl(name: str, info: dict, results: Results, ip: str, port: int):
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
        ssock = context.wrap_socket(sock, server_hostname=ip)

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
            and not_recv in res.decode()
        ):
            vulns = {}
            vulns["name"] = name
            vulns["description"] = info["description"]
            vulns["severity"] = info["severity"]
            results.set_vulns(vulns)

        ssock.close()

    except TimeoutError:
        pass

    except ConnectionResetError:
        pass

    except ssl.SSLError as e:
        pass
    # if "WRONG_VERSION_NUMBER" in str(e):


def print_tests(report: list):
    print("PORT \t PROTOCOL")

    for result in report:
        print(result)
