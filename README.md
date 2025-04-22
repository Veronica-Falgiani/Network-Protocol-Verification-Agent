# Network-Protocol-Verification-Agent

> Project for my thesis: "Design and Development of an Agent for Advanced Network Protocol Verification"

This project tests for vulnerabilities inside protocols used by a specific host. The provided tests can be expanded and tests for new protocols can be created from scratch.

Currently supported protocols: 
- ftp (ftps)
- ssh
- telnet
- smtp
- dns
- http (https)
- pop (pops)
- imap (imaps)
- smb
- gnutella
- ssl/tls

## Installation

You'll need to install the following python packages:
```
pip install scapy dnspython python-telnetlib-313-and-up-3.13.1-3 matplotlib numpy
```

### Self Signed Certification

For tls/ssl protocols to work you need to create a Self-Signed Certificate. 
To do this, install `OpenSSL`. 

Create a `cert/` folder and initialize the private key and Certificate Signing Request:
```
openssl req -newkey rsa:2048 -keyout domain.key -out domain.csr
```

Then create the Self-Signed Certificate using:
```
openssl x509 -signkey domain.key -in domain.csr -req -days 365 -out domain.crt
```

**!!! Do not rename the files used in the commands !!!**

## Usage

Te program needs **sudo** privileges to scan and execute the test

```
usage: main.py [-h] [-v] [-hs HOST_SCAN] [-ps PORT_SCAN] ports host

Agent for Advanced Network Protocol Verification

positional arguments:
  ports                 Single port [x], all ports [all], multiple ports [x,y,z] or port range [x:y] to scan
  host                  Host to scan using ipv4 address

options:
  -h, --help            Show this help message and exit
  -v, --verbose         Increasse output verbosity
  -hs, --host_scan HOST_SCAN
                        Host scan to execute: [p]ing, [s]yn, [a]ck, [u]dp (ping scan will be used by default)
  -ps, --port_scan PORT_SCAN
                        Port scan to execute: [c]onnect, [s]yn, [f]in, [n]ull, [x]mas, [u]dp (connect scan will be used by default, others need sudo permissions)
```

## Modifying and creating tests

Tests are written in __json__ format.

### Modify

Test if the port is open:

Test the response by sending a message:

Test the response by sending more than one messages:

### Create

The template for creating a test file is the following:
