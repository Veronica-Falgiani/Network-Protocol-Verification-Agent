import subprocess
import sys
import terminal_colors


# Check if the host is up
def ping_scan(ip: str):
    out = subprocess.run((["ping", "-c", "4", ip]), capture_output=True)
    result = out.stdout.decode()

    if "0 received" in result:
        print(
            terminal_colors.bcolors.WARNING
            + "Host is down"
            + terminal_colors.bcolors.ENDC
        )
        sys.exit()
    else:
        print(
            terminal_colors.bcolors.OKGREEN
            + "Host is up\n"
            + terminal_colors.bcolors.ENDC
        )


def arp_scan(ip: str):
    pass


def tcp_syn_scan(ip: str):
    pass


def tcp_ack_scan(ip: str):
    pass


def udp_scan(ip: str):
    pass


def ip_protocol_scan(ip: str):
    pass
