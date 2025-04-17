# Network-Protocol-Verification-Agent

Project for my thesis: "Design and Development of an Agent for Advanced Network Protocol Verification"



Supported protocols: 
- ftp
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



## Self Signed Certification

For tls/ssl protocols to work you need to create a Self-Signed Certificate. 

To do this, install OpenSSL. 

Go into the ‘src/cert/‘ folder and create the private key:
‘‘‘
openssl genrsa -des3 -out domain.key 2048
‘‘‘

Then create the Self-Signed Certificate using:
‘‘‘
openssl x509 -signkey domain.key -in domain.csr -req -days 365 -out domain.crt
‘‘‘

!!! Do not change the names of the created files, just copy and paste the commands !!!

## Creating tests


