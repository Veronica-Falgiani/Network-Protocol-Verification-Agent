class Results:
    def __init__(self, port, prot, service):
        self.port = port
        self.prot = prot
        self.service = service
        self.prot_max_misconfigs = 0
        self.prot_max_auth_misconfigs = 0
        self.serv_max_misconfigs = 0
        self.serv_max_auth_misconfigs = 0
        self.vuln_misconfigs = []
        self.vuln_auth_misconfigs = []
        self.unsafe_ver = False
        self.unsafe_ver_cve = []
        self.unsafe_tls = False
        self.prot_auth = False
        self.serv_auth = False

    def __str__(self):
        string = f"{str(self.port):<10s} {self.prot:<15s} {self.service:<100s}\n|\n"

        # Print if the service version is vulnerable
        string += "| --------------- VERSION CHECK ---------------\n"
        if self.unsafe_ver:
            string += (
                "|\\___ THIS SERVICE VERSION IS VULNERABLE AND NEEDS TO BE UPDATED!\n"
            )
            string += "|     reference:\n"
            for cve in self.unsafe_ver_cve:
                cve_number = cve.split("?id=")[1]
                string += f"|     - {cve_number}: {cve}\n"

            string += "|\n"
        else:
            string += "|\\___ The service version is not vulnerable.\n|\n"

        # Print if the ssl/tls version is outdated
        if "TLS" in self.service or "SSL" in self.service:
            string += "| --------------- SSL/TLS CHECK ---------------\n"
            if self.unsafe_tls:
                string += "|\\___ THE SERVICE USES A DEPRECATED SSL/TLS PROTOCOL! \n|\n"
            else:
                string += "|\\___ The service uses the currently supported SSL/TLS protocol  \n|\n"

        # Print all the information about the tests
        string += "| --------------- MISCONFIGURATIONS ---------------\n"
        if (self.prot_max_misconfigs + self.serv_max_misconfigs) == 0:
            string += "|\\___ No tests found for this protocol\n"
        elif len(self.vuln_misconfigs) == 0:
            string += "|\\___ The protocol has been tested and no misconfigurations have been found\n"
        else:
            for vuln in self.vuln_misconfigs:
                string += f"|\\___ {vuln['name']}\n"
                string += f"|     description: {vuln['description']}\n"
                string += f"|     severity: {vuln['severity']}\n"

        string += (
            "|\n| --------------- AUTHENTICATED MISCONFIGURATIONS ---------------\n"
        )
        if (self.prot_max_auth_misconfigs + self.serv_max_auth_misconfigs) == 0:
            string += "|\\___ No tests found for this protocol\n"
        elif not self.prot_auth and not self.serv_auth:
            string += "|\\___ No credentials were given\n"
        elif len(self.vuln_auth_misconfigs) == 0:
            string += "|\\___ The protocol has been tested and no misconfigurations have been found\n"
        else:
            for vuln in self.vuln_auth_misconfigs:
                string += f"|\\___ {vuln['name']}\n"
                string += f"|     description: {vuln['description']}\n"
                string += f"|     severity: {vuln['severity']}\n"

        string += "\n\n"

        return string

    def __json__(self):
        repr = {
            "port": self.port,
            "protocol": self.prot,
            "service": self.service,
            "unsafe_version": self.unsafe_ver,
            "unsafe_version_cve": self.unsafe_ver_cve,
            "misconfigurations": self.vuln_misconfigs,
            "auth_misconfigurations": self.vuln_auth_misconfigs,
        }

        return repr

    def add_prot_max(self, prot_max_misconfigs: int, prot_max_auth_misconfigs: int):
        self.prot_max_misconfigs = prot_max_misconfigs
        self.prot_max_auth_misconfigs = prot_max_auth_misconfigs

    def add_serv_max(self, serv_max_misconfigs: int, serv_max_auth_misconfigs: int):
        self.serv_max_misconfigs = serv_max_misconfigs
        self.serv_max_auth_misconfigs = serv_max_auth_misconfigs

    def set_misconfigs(self, vulns: dict):
        self.vuln_misconfigs.append(vulns)

    def set_auth_misconfigs(self, vulns: dict):
        self.vuln_auth_misconfigs.append(vulns)
