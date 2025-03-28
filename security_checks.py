import ssl
import socket
import whois
import dns.resolver
import requests
from datetime import datetime

class SecurityChecker:
    def __init__(self):
        self.ip_reputation_api = "958eb50176138b06b2976f7dcefafe305d159f5c9fac10ba0d8daa909c7d6a1e113b0be9f5844fd6"  

    def check_ssl(self, domain):
        try:
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    return {
                        'has_ssl': True,
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'expiry': cert['notAfter'],
                        'valid': True
                    }
        except:
            return {'has_ssl': False, 'valid': False}

    def check_dns_records(self, domain):
        try:
            results = {}
            for record_type in ['A', 'MX', 'NS', 'TXT']:
                try:
                    answers = dns.resolver.resolve(domain, record_type)
                    results[record_type] = [str(rdata) for rdata in answers]
                except:
                    results[record_type] = []
            return results
        except:
            return {}

    def check_whois(self, domain):
        try:
            w = whois.whois(domain)
            return {
                'registrar': w.registrar,
                'creation_date': w.creation_date,
                'expiration_date': w.expiration_date,
                'last_updated': w.updated_date,
                'status': w.status,
                'name_servers': w.name_servers
            }
        except:
            return {}

    def check_ip_reputation(self, ip):
        try:
            response = requests.get(f"https://api.abuseipdb.com/api/v2/check?ipAddress={ip}",
                                 headers={'Key': self.ip_reputation_api})
            return response.json()
        except:
            return {}

    def reverse_dns_lookup(self, ip):
        try:
            return socket.gethostbyaddr(ip)[0]
        except:
            return None
