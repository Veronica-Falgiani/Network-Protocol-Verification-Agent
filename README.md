# Vulnerability Assessment Tool for Advanced Network Protocols

> Project for my thesis: "Design and Development of a Vulnerability Assessment Tool for Advanced Network Protocol Verification"

A modular vulnerability scanner written in python. Tests for protocols and services are written in Json files.

Currently supported protocols: 
- ftp (ftps)
- ssh
- telnet
- smtp (smtps)
- dns
- http (https)
- pop (pops)
- imap (imaps)
- smb
- mqtt (mqtts)
- nfs
- ssl/tls

## Installation

The script has been tested for **python version 3.13**

### Required packages

`nfs-utils` is required for the nfs scan to work. Install it with your preferred package manager.

### Required python packages

You'll need to install the required python packages using the `requirements.txt` file:
```
pip install -r requirements.txt
```

## Usage

### Command line

The program needs **sudo** privileges to scan and execute scans and tests

```
usage: main.py [-h] [-v] [-nt] [-hs HOST_SCAN] [-ps PORT_SCAN] ports host

Agent for Advanced Network Protocol Verification. This program needs sudo privileges to run.

positional arguments:
  ports                 Single port [x], multiple ports [x,y,z],  port range [x:y] to scan or all ports [all]
  host                  Host to scan using ipv4 address

options:
  -h, --help            Show this help message and exit
  -v, --verbose         Increase output verbosity
  -nt, --no_tests       Scans the target for services but doesn't execute a vulnerability scan
  -hs, --host_scan HOST_SCAN
                        Host scan to execute: [p]ing, [s]yn, [a]ck, [u]dp (ping scan will be used by default)
  -ps, --port_scan PORT_SCAN
                        Port scan to execute: [c]onnect, [s]yn, [f]in, [n]ull, [x]mas, [u]dp (connect scan will be used by default)
```

### Results

Results can be viewed in the `res/` directory.

There are three types of files:
- .log: human readable text file
- .json: json file that can be processed by other programs
- .html: easy to navigate results with graphs

## Modifying and creating tests

Tests are written in __json__ and there are two types: one for the protocols (inside `tests/prot` folder) and one for the services (inside `tests/serv` folder)

### Tests for protocols

The base template for the json must have these items in order to work:
```
{
  "vulns": {},
  "login": "",
  "auth_vulns": {},
  "serv_names": []
}
```

### Tests for services

The base template for the json must have these items in order to work:
```
{
  "vulns": {},
  "login": {},
  "auth_vulns": {},
  "vuln_serv_version": {}
}
```

---

#### misconfigs/auth_misconfigs

You can concatenate one or more tests inside misconfigs and auth_misconfigs.

**Check if a vulnerable port is open:**
```
"IS OPEN": {
  "description": "Telnet is an old network protocol that provides insecure access to computers over a network. Due to security vulnerabilities, its usage is not recommended, and more secure alternatives like SSH are preferred.",
  "severity": "high"
}
```

- description: why is the open port a vulnerability issue
- severity: "low", "medium", "high"

**Simple test sending and receiving commands:**
```
"ANONYMOUS LOGIN ENABLED" :{
  "description": "Anonymous login is enabled, everyone can access the service",
  "send": "\n~~USER anonymous\n~~PASS\n",
  "recv": "230",
  "severity": "high"
},
```

- description: why is the misconfiguration a vulnerability issue
- send: the command to send. If you need to send more commands, separate them with `~~` (Ex. `\n~~USER anonymous\n~~PASS\n`)
- recv or not_recv: specify the packets we receive/not receive to recognise if there is a vulnerability
- severity: "low", "medium", "high"

---

#### login

The commands used to login into the service.

```
"login": {
  "send_str": "\n~~USER _username_\n~~PASS _password_\n",
  "recv_str": "230 Login successful."
},
```

- send_str: the commands that need to be sent for login. Separate more than one command with the `~~` characters and use `_username_` and `_password_` as placeholders for credentials
- recv_str: the string we recieve when the login is correct

---

#### serv_names

A list of all the service names that have a test inside `tests/serv`

```
"serv_names": [
  "vsftpd",
  "proftpd"
]
```

---

#### vuln_serv_version

A list of service versions that are vulnerable and their respective CVEs.

```
  "vuln_serv_version": {
    "2.2.8": ["https://www.cve.org/CVERecord?id=CVE-2008-2364", 
      "https://www.cve.org/CVERecord?id=CVE-2022-40309"]
  }
```

**For more examples, check the tests folder**
