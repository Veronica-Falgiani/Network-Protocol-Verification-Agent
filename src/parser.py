import argparse

# python3 main.py -hs A -ss B -p 1234 -h 1234


def parser():
    parser = argparse.ArgumentParser(
        prog="Vlastrax",
        description="Agente per la verifica di protocolli avanzati",
        add_help=False,
    )

    parser.add_argument("--help", action="help", help="show this help message and exit")
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Increasse output verbosity"
    )
    parser.add_argument("-hs", "--host_scan", help="Host scan to execute")
    parser.add_argument("-ss", "--service_scan", help="Service scan to execute")
    parser.add_argument(
        "ports", help="Ports to scan. Single ports, sequential (:), multiple (,)"
    )
    parser.add_argument("host", help="Host to scan")

    args = parser.parse_args()

    return args
