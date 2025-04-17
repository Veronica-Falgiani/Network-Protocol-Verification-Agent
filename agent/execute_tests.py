import json
import os
import socket

base_dir = os.path.dirname(__file__)


def print_test(services: dict, ip: str) -> dict:
    report = {}
    results = {}

    print("PORT \t PROTOCOL")

    for port, prot in services.items():
        # Reads from the test files we provide
        print(f"\n{port} \t {prot}")
        rel_path = "../tests/" + prot.lower() + "_test.json"
        print(base_dir, rel_path)
        path = os.path.join(base_dir, rel_path)

        try:
            with open(path) as file:
                test_file = json.load(file)
                tests = test_file["tests"]

                for name, info in tests.items():
                    # Complex ssl/tls test: establishes a connection and then sends a message and compares results
                    if "SSL" in name or name == "HTTPS":
                        test_ssl(name, info, results, ip, port)

                    # Complex test: sends a message and compares the results
                    if "recv" in info:
                        test(name, info, results, ip, port)

                    # Simple test: checks if the port is open
                    else:
                        print(f"|\\_ {name}")
                        print(f"|   severity: {info['severity']}")
                        results[name] = info

                report[port] = results.copy()
                results.clear()

        except FileNotFoundError:
            print("|\\_ --- NO TESTS FOUND FOR THIS PROTOCOL ---")

    return report


def test(name: str, info: dict, results: dict, ip: str, port: int):
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
            print(send)
            sock.send(send.encode())
            res = sock.recv(1024)
            print(res.decode())

        # Compares the received message to the one in the json
        if (
            recv is not None
            and recv in res.decode()
            or not_recv is not None
            and not_recv in res.decode()
        ):
            print(f"|\\_ {name}")
            print(f"|   severity: {info['severity']}")
            results[name] = info

        sock.close()

    except TimeoutError:
        pass


def test_ssl(name: str, info: dict, results: dict, ip: str, port: int):
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
            print(f"|\\_ {name}")
            print(f"|   severity: {info['severity']}")
            results[name] = info

        sock.close()

    except TimeoutError:
        pass
