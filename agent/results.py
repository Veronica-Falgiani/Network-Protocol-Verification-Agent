class Results:
    def __init__(self, port, prot, service, max_vulns):
        self.port = port
        self.prot = prot
        self.service = service
        self.max_vulns = max_vulns
        self.vulns = []

    def __str__(self):
        string = ""

        string += f"{self.port} \t {self.prot}\t {self.service}\n"

        if self.max_vulns == 0:
            string += "|\\_ ---- NO TESTS FOUND FOR THIS PROTOCOL ----\n"

        elif len(self.vulns) == 0:
            string += "|\\_ ---- THE SERVICE HAS NO VULNERABILITIES ----\n"

        for vuln in self.vulns:
            string += f"|\\_ {vuln['name']}\n"
            string += f"|   description: {vuln['description']}\n"
            string += f"|   severity: {vuln['severity']}\n"

        return string

    def get_port(self):
        return self.port

    def get_prot(self):
        return self.prot

    def get_service(self):
        return self.service

    def get_max_vulns(self):
        return self.max_vuln

    def get_vulns(self):
        return self.vulns

    def set_port(self, port):
        self.port = port

    def set_prot(self, prot):
        self.prot = prot

    def set_service(self, service):
        self.service = service

    def set_max_vulns(self, max_vulns):
        self.max_vulns = max_vulns

    def set_vulns(self, vulns: dict):
        self.vulns.append(vulns)
