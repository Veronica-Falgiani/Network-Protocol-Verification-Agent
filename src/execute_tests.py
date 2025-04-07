import json
import os
from terminal_colors import print_warning, print_fail, print_ok

base_dir = os.path.dirname(__file__)


def print_test(services: dict):
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
                if "recv" in info:
                    test(name, info, results)
                else:
                    print("|")
                    print(f"|\\_ {name}")
                    print(f"|   severity: {info['severity']}")
                    results[name] = info

            report[port] = results.copy()
            results.clear()

    return report


def test(name, info, results):
    send = info["send"]
    recv = info["recv"]
    res = "200"

    # Send and receive packages

    if recv == res:
        print("|")
        print(f"|\\_ {name}")
        print(f"|   severity: {info['severity']}")
        results[name] = info
