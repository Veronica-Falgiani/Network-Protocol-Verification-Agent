class Results:
    def __init__(self, port, prot, service):
        self.port = port
        self.prot = prot
        self.service = service
        self.prot_max_vulns = 0
        self.prot_max_auth_vulns = 0
        self.serv_max_vulns = 0
        self.serv_max_auth_vulns = 0
        self.found_vulns = []
        self.found_auth_vulns = []
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
        string += "| --------------- VULNERABILITIES ---------------\n"
        if (self.prot_max_vulns + self.serv_max_vulns) == 0:
            string += "|\\___ No tests found for this protocol\n"
        elif len(self.found_vulns) == 0:
            string += "|\\___ The protocol has been tested and no vulnearbilities have been found\n"
        else:
            for vuln in self.found_vulns:
                string += f"|\\___ {vuln['name']}\n"
                string += f"|     description: {vuln['description']}\n"
                string += f"|     severity: {vuln['severity']}\n"

        string += (
            "|\n| --------------- AUTHENTICATED VULNERABILITIES ---------------\n"
        )
        if (self.prot_max_auth_vulns + self.serv_max_auth_vulns) == 0:
            string += "|\\___ No tests found for this protocol\n"
        elif not self.prot_auth and not self.serv_auth:
            string += "|\\___ No credentials were given\n"
        elif len(self.found_auth_vulns) == 0:
            string += "|\\___ The protocol has been tested and no vulnerabilities have been found\n"
        else:
            for vuln in self.found_auth_vulns:
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
            "vulnerabilities": self.found_vulns,
            "auth_vulnerabilities": self.found_auth_vulns,
        }

        if "SSL" in self.service or "TLS" in self.service:
            position = list(repr.keys()).index('misconfigurations')
            items = list(repr.items())
            items.insert(position, ("unsafe_tls", self.unsafe_tls))
            repr = dict(items)

        return repr

    def add_prot_max(self, prot_max_vulns: int, prot_max_auth_vulns: int):
        self.prot_max_vulns = prot_max_vulns
        self.prot_max_auth_vulns = prot_max_auth_vulns

    def add_serv_max(self, serv_max_vulns: int, serv_max_auth_vulns: int):
        self.serv_max_vulns = serv_max_vulns
        self.serv_max_auth_vulns = serv_max_auth_vulns

    def set_vulns(self, vulns: dict):
        self.found_vulns.append(vulns)

    def set_auth_vulns(self, vulns: dict):
        self.found_auth_vulns.append(vulns)
