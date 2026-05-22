#!/usr/bin/env python3
"""
TLS Certificate Inspector
Requires: pip install cryptography

Usage:
  python tls_inspector.py example.com
  python tls_inspector.py example.com 8443
"""

import ssl
import socket
import datetime
import sys
import fnmatch
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, ec, dsa

GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

def ok(msg):     return f"{GREEN}✔  {msg}{RESET}"
def warn(msg):   return f"{YELLOW}⚠  {msg}{RESET}"
def fail(msg):   return f"{RED}✘  {msg}{RESET}"
def info(msg):   return f"{CYAN}   {msg}{RESET}"
def header(msg): return f"\n{BOLD}{msg}{RESET}"


def fetch_cert(hostname: str, port: int = 443):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((hostname, port), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
            der = ssock.getpeercert(binary_form=True)
            protocol = ssock.version() or "unknown"
    cert = x509.load_der_x509_certificate(der, default_backend())
    return cert, protocol


def days_left(cert) -> int:
    now = datetime.datetime.now(datetime.timezone.utc)
    return (cert.not_valid_after_utc - now).days


def get_sans(cert) -> list:
    try:
        ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        return ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        return []


def key_info(cert):
    pub = cert.public_key()
    if isinstance(pub, rsa.RSAPublicKey):
        return "RSA", pub.key_size
    elif isinstance(pub, ec.EllipticCurvePublicKey):
        return "ECDSA", pub.key_size
    elif isinstance(pub, dsa.DSAPublicKey):
        return "DSA", pub.key_size
    return "Unknown", 0


def hostname_matches(hostname: str, cert) -> bool:
    sans = get_sans(cert)
    if not sans:
        try:
            cn = cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
            sans = [cn]
        except IndexError:
            return False
    return any(fnmatch.fnmatch(hostname, name) for name in sans)


def print_details(hostname: str, cert, protocol: str):
    alg = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "unknown"
    key_alg, key_size = key_info(cert)
    sans = get_sans(cert)
    dl = days_left(cert)

    print(header("── Certificate details ─────────────────────────────"))
    print(info(f"Host        : {hostname}"))
    print(info(f"Subject     : {cert.subject.rfc4514_string()}"))
    print(info(f"Issuer      : {cert.issuer.rfc4514_string()}"))
    print(info(f"Valid from  : {cert.not_valid_before_utc.strftime('%Y-%m-%d')}"))
    print(info(f"Expires     : {cert.not_valid_after_utc.strftime('%Y-%m-%d')}  ({dl} days)"))
    print(info(f"Key         : {key_alg} {key_size}-bit"))
    print(info(f"Signature   : {alg}"))
    print(info(f"Protocol    : {protocol}"))
    if sans:
        display = sans[:6]
        more = f" … (+{len(sans)-6} more)" if len(sans) > 6 else ""
        print(info(f"SANs        : {', '.join(display)}{more}"))


def print_checks(hostname: str, cert, protocol: str):
    alg = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "unknown"
    key_alg, key_size = key_info(cert)
    dl = days_left(cert)
    issues = []

    print(header("── Security checks ─────────────────────────────────"))

    # 1. Expiry
    if dl <= 0:
        print(fail(f"Certificate EXPIRED {abs(dl)} days ago"))
        issues.append("Expired certificate")
    elif dl <= 14:
        print(warn(f"Expires in {dl} days — renew immediately"))
        issues.append(f"Expiring in {dl} days")
    elif dl <= 30:
        print(warn(f"Expires in {dl} days — renew soon"))
        issues.append(f"Expiring in {dl} days")
    else:
        print(ok(f"Valid for {dl} more days"))

    # 2. Hostname match
    if hostname_matches(hostname, cert):
        print(ok("Hostname matches certificate"))
    else:
        print(fail(f"Hostname '{hostname}' does NOT match certificate SANs"))
        issues.append("Hostname mismatch")

    # 3. Signature algorithm
    weak_sigs = {"md5", "sha1"}
    if any(w in alg.lower() for w in weak_sigs):
        print(fail(f"Weak signature algorithm: {alg}  (use SHA-256+)"))
        issues.append(f"Weak signature: {alg}")
    else:
        print(ok(f"Strong signature algorithm: {alg}"))

    # 4. Key size
    if key_alg == "RSA" and key_size < 2048:
        print(fail(f"RSA key too small: {key_size}-bit  (2048+ required)"))
        issues.append(f"Weak RSA key: {key_size}-bit")
    elif key_alg == "RSA" and key_size < 3072:
        print(warn(f"RSA key is {key_size}-bit  (3072+ preferred long-term)"))
    else:
        print(ok(f"Key size adequate: {key_alg} {key_size}-bit"))

    # 5. Protocol version
    old_protocols = {"SSLv2", "SSLv3", "TLSv1", "TLSv1.1"}
    if protocol in old_protocols:
        print(fail(f"Old protocol in use: {protocol}  (use TLS 1.2+)"))
        issues.append(f"Old protocol: {protocol}")
    else:
        print(ok(f"Modern protocol: {protocol}"))

    # 6. Self-signed
    if cert.issuer == cert.subject:
        print(fail("Self-signed certificate (not trusted by browsers)"))
        issues.append("Self-signed")
    else:
        print(ok("Issued by a CA (not self-signed)"))

    # 7. Basic constraints
    try:
        bc = cert.extensions.get_extension_for_class(x509.BasicConstraints)
        if bc.value.ca:
            print(warn("CA certificate used — not intended for servers"))
            issues.append("CA cert used as server cert")
        else:
            print(ok("End-entity certificate (CA:FALSE)"))
    except x509.ExtensionNotFound:
        print(warn("No BasicConstraints extension found"))

    # 8. Subject Alternative Names present
    sans = get_sans(cert)
    if sans:
        print(ok(f"SANs present ({len(sans)} name(s))"))
    else:
        print(warn("No Subject Alternative Names — some clients may reject this"))
        issues.append("No SANs")

    # Summary
    print(header("── Summary ─────────────────────────────────────────"))
    if not issues:
        print(f"{GREEN}{BOLD}  All checks passed. Certificate looks good.{RESET}\n")
    else:
        print(f"{RED}{BOLD}  {len(issues)} issue(s) found:{RESET}")
        for i in issues:
            print(f"  {RED}• {i}{RESET}")
        print()


def main():
    if len(sys.argv) < 2:
        print(f"Usage: python {sys.argv[0]} <hostname> [port]")
        print(f"  e.g. python {sys.argv[0]} example.com")
        print(f"       python {sys.argv[0]} example.com 8443")
        sys.exit(1)

    hostname = sys.argv[1].replace("https://", "").replace("http://", "").strip("/")
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 443

    print(f"\n{BOLD}TLS Certificate Inspector{RESET}")
    print(f"Connecting to {CYAN}{hostname}:{port}{RESET} …")

    try:
        cert, protocol = fetch_cert(hostname, port)
    except ssl.SSLError as e:
        print(fail(f"SSL error: {e}"))
        sys.exit(1)
    except socket.timeout:
        print(fail(f"Connection timed out: {hostname}:{port}"))
        sys.exit(1)
    except OSError as e:
        print(fail(f"Connection failed: {e}"))
        sys.exit(1)

    print_details(hostname, cert, protocol)
    print_checks(hostname, cert, protocol)


if __name__ == "__main__":
    main()
