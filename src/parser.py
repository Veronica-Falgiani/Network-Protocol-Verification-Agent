import argparse

# python3 main.py -hs p -ps s 100:200 192.168.0.1


def parser():
    parser = argparse.ArgumentParser(
        prog="main.py",
        description="Agente per la verifica di protocolli avanzati",
        add_help=False,
        usage='use "%(prog)s --help" for more information',
        formatter_class=argparse.RawTextHelpFormatter,
    )

    parser.add_argument("--help", action="help", help="Show this help message and exit")
    parser.add_argument(
        "-v", "--verbose", action="store_true", help="Increasse output verbosity"
    )
    parser.add_argument(
        "-hs",
        "--host_scan",
        help="Host scan to execute: [p]ing, [s]yn, [a]ck, [u]dp (ping scan will be used by default)",
    )
    parser.add_argument(
        "-ps",
        "--port_scan",
        help="Port scan to execute: [c]onnect, [s]yn, [f]in, [n]ull, [x]mas, [u]dp (connect scan will be used by default, others need sudo permissions)",
    )
    parser.add_argument(
        "ports",
        help="Single port [x], all ports [all], multiple ports [x,y,z] or port range [x:y] to scan",
    )
    parser.add_argument("host", help="Host to scan using ipv4 address")

    args = parser.parse_args()

    return args
