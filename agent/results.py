class Results:
    def __init__(self, port, prot, service, max_vulns):
        self.port = port
        self.prot = prot
        self.service = service
        self.max_vulns = max_vulns
        self.vulns = []
        self.unsafe_ver = False
        self.unsafe_ver_cve = ""
        self.unsafe_tls = False

    def __str__(self):
        string = f"{str(self.port):<10s} {self.prot:<15s} {self.service:<100s}\n"

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
        string += "| --------------- POSITIVE VULNERABILITY TESTS ---------------\n"
        if len(self.vulns) == 0:
            string += "|\\___ No tests found\n"
        else:
            for vuln in self.vulns:
                string += f"|\\___ {vuln['name']}\n"
                string += f"|     description: {vuln['description']}\n"
                string += f"|     severity: {vuln['severity']}\n"

        return string

    def set_vulns(self, vulns: dict):
        self.vulns.append(vulns)
