import json
import os

base_dir = os.path.dirname(__file__)


def test(services: dict):
    for port, prot in services.items():
        rel_path = "tests/" + prot.lower() + "_test.json"
        path = os.path.join(base_dir, rel_path)
        with open(path) as file:
            info = json.load(file)
            print(info["tests"])
