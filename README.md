# Network-Protocol-Verification-Agent

> Project for my thesis: "Design and Development of an Agent for Advanced Network Protocol Verification"

This project tests for vulnerabilities inside protocols used by a specific host. The provided tests can be expanded and tests for new protocols can be created from scratch.

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

The program needs **sudo** privileges to scan and execute the test

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

## Modifying and creating tests

Tests are written in __json__ format and need to be inserted into the `tests/` folder.

The base template for the script needs to contain the following things in order to work:
```
{
  "misconfigs": {
  },
  "login": "",
  "auth_misconfigs": {
  },
  "vuln_services": {
  }
}
```

To populate the fields you need to write what you want like this:

### misconfigs/auth_misconfigs

You can concatenate one or more tests inside misconfigs and auth_misconfigs.

**Check if a vulnerable port is open:**
```
"IS OPEN": {
  "description": "",
  "severity": ""
}
```

- description: why is the open port a vulnerability issue
- severity: "low", "medium", "high"

**Simple test sending and receiving commands:**
```
"MISCONFIG NAME": {
  "description": "",
  "send": "",
  "recv/not_recv": "",
  "severity": ""
}
```

- MISCONFIG NAME: how you want to call the misconfiguration
- description: why is the misconfiguration a vulnerability issue
- send: the command to send. If you need to send more commands, separate them with `~~` (Ex. `\n~~USER anonymous\n~~PASS\n`)
- recv or not_recv: specify the packets we receive/not receive to recognise if there is a vulnerability
- severity: "low", "medium", "high"

### login

The strings used to login into the service

```
"login": "\n~~USER _username_\n~~PASS _password_\n"
```

- Separate more commands with the `~~` characters
- Use `_username_` and `_password_` as placeholders for credentials 

### vuln_services

You need to specify the vulnerable version of the service based on the banners you receive from the server
Services can be concatenated

Ex.
```
"SERVICE NAME": {
  "version": "https://www.cve.org/CVERecord?id=CVE-****-****",
  "version": "https://www.cve.org/CVERecord?id=CVE-****-****"
}
```

- SERVICE NAME: the name of the service given by the banner
- version: the version of the service given by the banner (ex. "2.3.4")
- cve link: the link to the CVE page of the vulnerable service version

**For more examples, check the tests folder**
