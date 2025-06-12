class Results:
    def __init__(self, port, prot, service, max_misconfigs, max_auth_misconfigs):
        self.port = port
        self.prot = prot
        self.service = service
        self.max_misconfigs = max_misconfigs
        self.max_auth_misconfigs = max_auth_misconfigs
        self.vuln_misconfigs = []
        self.vuln_auth_misconfigs = []
        self.unsafe_ver = False
        self.unsafe_ver_cve = ""
        self.unsafe_tls = False

    def __str__(self):
        string = f"{str(self.port):<10s} {self.prot:<15s} {self.service:<100s}\n|\n"

        # Print if the service version is vulnerable
        string += "| --------------- VERSION CHECK ---------------\n"
        if self.unsafe_ver:
            string += "|\\___ THE SERVICE IS VULNERABLE AND NEEDS TO BE UPDATED!\n"
            string += f"|     reference: {self.unsafe_ver_cve}\n|\n"
        else:
            string += "|\\___ The service is not vulnerable\n|\n"

        # Print if the ssl/tls version is outdated
        if "TLS" in self.service or "SSL" in self.service:
            string += "| --------------- SSL/TLS CHECK ---------------\n"
            if self.unsafe_tls:
                string += "|\\___ THE SERVICE USES A DEPRECATED SSL/TLS PROTOCOL! \n|\n"
            else:
                string += "|\\___ The service uses the current SSL/TLS protocol  \n|\n"

        # Print all the information about the tests
        string += "| --------------- MISCONFIGURATIONS ---------------\n"
        if len(self.vuln_misconfigs) == 0:
            string += "|\\___ No misconfigurations found\n"
        else:
            for vuln in self.vuln_misconfigs:
                string += f"|\\___ {vuln['name']}\n"
                string += f"|     description: {vuln['description']}\n"
                string += f"|     severity: {vuln['severity']}\n"

        string += (
            "|\n| --------------- AUTHENTICATED MISCONFIGURATIONS ---------------\n"
        )
        if len(self.vuln_auth_misconfigs) == 0:
            string += "|\\___ No authenticated misconfigurations found\n"
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

    def set_misconfigs(self, vulns: dict):
        self.vuln_misconfigs.append(vulns)

    def set_auth_misconfigs(self, vulns: dict):
        self.vuln_auth_misconfigs.append(vulns)
