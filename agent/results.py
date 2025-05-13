class Results:
    def __init__(self, port, prot, service, max_vulns):
        self.port = port
        self.prot = prot
        self.service = service
        self.max_vulns = max_vulns
        self.vulns = []
        self.unsafe_ver = False

    def __str__(self):
        string = f"{str(self.port):<10s} {self.prot:<15s} {self.service:<100s}\n"

        if self.max_vulns == 0:
            string += "|\\_ ---- NO TESTS FOUND FOR THIS PROTOCOL ----\n"

        elif len(self.vulns) == 0:
            string += "|\\_ ---- THE SERVICE HAS NO VULNERABILITIES ----\n"

        for vuln in self.vulns:
            string += f"|\\_ {vuln['name']}\n"
            string += f"|   description: {vuln['description']}\n"
            string += f"|   severity: {vuln['severity']}\n"

        return string

    def set_vulns(self, vulns: dict):
        self.vulns.append(vulns)
