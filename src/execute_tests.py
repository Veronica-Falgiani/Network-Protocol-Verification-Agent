import json
from logging import NullHandler
import os
import socket
from terminal_colors import print_warning, print_fail, print_ok
import paramiko

base_dir = os.path.dirname(__file__)


def print_test(services: dict, ip: str) -> dict:
    report = {}
    results = {}

    print("PORT \t PROTOCOL")

    for port, prot in services.items():
        print(f"\n{port} \t {prot}")
        rel_path = "tests/" + prot.lower() + "_test.json"
        path = os.path.join(base_dir, rel_path)

        with open(path) as file:
            test_file = json.load(file)
            tests = test_file["tests"]

            for name, info in tests.items():
                if prot == "SSH":
                    test_ssh(name, info, results, ip, port)
                elif "recv" in info:
                    test(name, info, results, ip, port)
                else:
                    print("|")
                    print(f"|\\_ {name}")
                    print(f"|   severity: {info['severity']}")
                    results[name] = info

            report[port] = results.copy()
            results.clear()

    return report


def test(name: str, info: dict, results: dict, ip: str, port: int):
    recv = None
    not_recv = None

    send_str = info["send"]
    send_list = send_str.split("~")

    if "recv" in info:
        recv = info["recv"]
    elif "not_recv" in info:
        not_recv = info["not_recv"]

    print(recv, not_recv, send_list)

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((ip, port))

        for send in send_list:
            print(send)
            sock.send(send.encode())
            res = sock.recv(1024)
            print(res.decode())

        if (
            recv is not None
            and recv in res.decode()
            or not_recv is not None
            and not_recv in res.decode()
        ):
            print("|")
            print(f"|\\_ {name}")
            print(f"|   severity: {info['severity']}")
            results[name] = info

        sock.close()

    except TimeoutError:
        pass


# Having to use paramiko to connect to ssh correctly
def test_ssh(name: str, info: dict, results: dict, ip: str, port: int):
    client = paramiko.client.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(ip, username="admin", password="")
    _stdin, _stdout, _stderr = client.exec_command("df")
    print(_stdout.read().decode())
    client.close()
