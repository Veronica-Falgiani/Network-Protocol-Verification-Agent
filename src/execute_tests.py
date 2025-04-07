import json
import os
from terminal_colors import print_warning, print_fail, print_ok

base_dir = os.path.dirname(__file__)


def print_test(services: dict):
    print("PORT \t PROTOCOL")

    for port, prot in services.items():
        print(f"\n{port} \t {prot}")
        rel_path = "tests/" + prot.lower() + "_test.json"
        path = os.path.join(base_dir, rel_path)

        with open(path) as file:
            test_file = json.load(file)
            tests = test_file["tests"]

            for name, info in tests.items():
                if "send" in info:
                    test(name, info)
                else:
                    print(f"|\\_ {name}")
                    print(f"|   severity: {info['severity']}")
                    print(f"|")


def test(name, info):
    send = info["send"]
    recv = info["recv"]
    res = "20"
    print(send, recv)

    # Send and receive packages

    if recv == res:
        print(f"|\\_ {name}")
        print(f"|   severity: {info['severity']}")
        print(f"|")
