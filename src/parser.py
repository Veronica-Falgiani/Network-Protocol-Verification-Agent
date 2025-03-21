import argparse

# python3 main.py -hs A -ss B -p 1234 -h 1234


def parser():
    parser = argparse.ArgumentParser(
        prog="main.py",
        description="Agente per la verifica di protocolli avanzati",
        add_help=False,
        usage='use "%(prog)s --help" for more information',
        formatter_class=argparse.RawTextHelpFormatter,
    )

    parser.add_argument("--help", action="help", help="show this help message and exit")
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Increasse output verbosity"
    )
    parser.add_argument("-hs", "--host_scan", help="Host scan to execute")
    parser.add_argument("-ss", "--service_scan", help="Service scan to execute")
    parser.add_argument(
        "ports",
        help="Ports to scan.\n - Single ports: 1234 \n - Sequential: 1000:2000 \n - Multiple 100,200,300",
    )
    parser.add_argument("host", help="Host to scan")

    args = parser.parse_args()

    return args
