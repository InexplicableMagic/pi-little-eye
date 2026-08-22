import os
import stat
import socket
import subprocess
import ipaddress
import shutil

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from datetime import datetime, timedelta, timezone
from pathlib import Path


class CertificateHandler:

    CERTIFICATES_DIR = str( (Path(__file__).parent / "../certificates").resolve() )

    # Root CA — install this one on clients to trust the leaf cert
    # Many operating system will recognise .crt extension as a certificate
    # This is intended to be downloaded and installed
    CA_CERTIFICATE_FNAME = "ca_cert.crt"
    CA_PRIVATE_KEY_FNAME = "ca_key.pem"
    CA_VALIDITY_DAYS = 3650  # 10 years

    CERTIFICATE_FNAME = "camera_cert.pem"
    PRIVATE_KEY_FNAME = "camera_key.pem"
    LEAF_VALIDITY_DAYS = 365
    # Renew certificate this number of days before expiry
    LEAF_RENEWAL_BUFFER_DAYS = 2

    # User-added SAN entries (e.g. via a CLI flag), persisted across restarts
    # and renewals so they aren't lost when the leaf is reissued.
    EXTRA_NAMES_FNAME = "additional_san_names.txt"

    def get_ca_cert_file_path():
        return os.path.join(CertificateHandler.CERTIFICATES_DIR, CertificateHandler.CA_CERTIFICATE_FNAME)

    def get_ca_key_file_path():
        return os.path.join(CertificateHandler.CERTIFICATES_DIR, CertificateHandler.CA_PRIVATE_KEY_FNAME)

    def get_cert_file_path():
        return os.path.join(CertificateHandler.CERTIFICATES_DIR, CertificateHandler.CERTIFICATE_FNAME)

    def get_key_file_path():
        return os.path.join(CertificateHandler.CERTIFICATES_DIR, CertificateHandler.PRIVATE_KEY_FNAME)

    def get_extra_names_file_path():
        return os.path.join(CertificateHandler.CERTIFICATES_DIR, CertificateHandler.EXTRA_NAMES_FNAME)

    def load_extra_names():
        path = CertificateHandler.get_extra_names_file_path()
        if not os.path.exists(path):
            return set()

        with open(path, "r") as f:
            return {line.strip() for line in f if line.strip()}

    def save_extra_names(names):
        path = CertificateHandler.get_extra_names_file_path()
        with open(path, "w") as f:
            for name in sorted(names):
                f.write(name + "\n")
        os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)

    def discover_dns_names():
        names = {"localhost"}

        try:
            hostname = socket.gethostname()
            if hostname:
                names.add(hostname)
                # Debian/Raspberry Pi OS advertises itself over mDNS as <hostname>.local
                names.add(f"{hostname}.local")
        except Exception:
            pass

        try:
            fqdn = socket.getfqdn()
            if fqdn and fqdn != "localhost":
                names.add(fqdn)
        except Exception:
            pass

        return names

    # Attempt to determine every possible name and IP address that the Pi might be known as
    # for the SAN list in the certicate
    def discover_ip_addresses():
        ips = {"127.0.0.1", "::1"}

        # `hostname -I` is standard on Raspberry Pi OS / Debian and lists
        # every IP assigned to every interface (wired, wifi, etc), which
        # covers cases a single-socket trick would miss.
        try:
            output = subprocess.check_output(["hostname", "-I"], text=True, timeout=2)
            for token in output.split():
                ips.add(token)
        except Exception:
            pass

        # Fallback / supplement: ask the OS which local address it would use
        # to reach the outside world. Doesn't actually send any traffic.
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            try:
                s.connect(("8.8.8.8", 80))
                ips.add(s.getsockname()[0])
            finally:
                s.close()
        except Exception:
            pass

        # Keep only strings that are actually valid IP addresses
        valid_ips = set()
        for ip in ips:
            try:
                ipaddress.ip_address(ip)
                valid_ips.add(ip)
            except ValueError:
                continue

        return valid_ips

    def update_tls_certificates():
        if not os.path.exists(CertificateHandler.CERTIFICATES_DIR):
            os.makedirs(CertificateHandler.CERTIFICATES_DIR)
            os.chmod(CertificateHandler.CERTIFICATES_DIR, stat.S_IRWXU)

        ca_cert_path = CertificateHandler.get_ca_cert_file_path()
        ca_key_path = CertificateHandler.get_ca_key_file_path()
        cert_path = CertificateHandler.get_cert_file_path()
        key_path = CertificateHandler.get_key_file_path()

        # Regenerate the CA if it doesn't exist or has expired.
        # If we regenerate the CA, the leaf must be reissued too, since the
        # old leaf was signed by a CA that no longer exists on disk.
        ca_regenerated = False
        if not os.path.exists(ca_cert_path) or not os.path.exists(ca_key_path):
            ca_regenerated = True
        elif CertificateHandler.test_if_certificate_expired(ca_cert_path):
            ca_regenerated = True

        if ca_regenerated:
            CertificateHandler.generate_ca_key_and_cert(ca_key_path, ca_cert_path)

        dns_names = CertificateHandler.discover_dns_names()
        ip_addresses = CertificateHandler.discover_ip_addresses()

        # Fold in any names the user has previously added via
        # add_dns_name_to_certificate(), so they aren't lost on renewal.
        extra_dns_names, extra_ip_addresses = CertificateHandler.split_names_by_type(
            CertificateHandler.load_extra_names()
        )
        dns_names |= extra_dns_names
        ip_addresses |= extra_ip_addresses

        leaf_needs_reissue = (
            ca_regenerated
            or not os.path.exists(cert_path)
            or not os.path.exists(key_path)
            or CertificateHandler.test_if_certificate_expired(cert_path, buffer_days=CertificateHandler.LEAF_RENEWAL_BUFFER_DAYS)
            or not CertificateHandler.certificate_covers_names(cert_path, dns_names, ip_addresses)
        )

        if leaf_needs_reissue:
            ca_private_key = CertificateHandler.load_private_key(ca_key_path)
            ca_certificate = CertificateHandler.load_certificate(ca_cert_path)
            CertificateHandler.generate_leaf_key_and_cert(
                ca_private_key, ca_certificate, key_path, cert_path, dns_names, ip_addresses
            )

    # Sorts a mixed set of names into (dns_names, ip_addresses) based on
    # whether each entry parses as a valid IP address.
    def split_names_by_type(names):
        dns_names = set()
        ip_addresses = set()
        for name in names:
            try:
                ipaddress.ip_address(name)
                ip_addresses.add(name)
            except ValueError:
                dns_names.add(name)
        return dns_names, ip_addresses

    def add_dns_name_to_certificate(additional_name):
        additional_name = additional_name.strip()
        if not additional_name:
            return

        ca_cert_path = CertificateHandler.get_ca_cert_file_path()
        ca_key_path = CertificateHandler.get_ca_key_file_path()
        cert_path = CertificateHandler.get_cert_file_path()
        key_path = CertificateHandler.get_key_file_path()

        if not os.path.exists(ca_cert_path) or not os.path.exists(ca_key_path):
            raise FileNotFoundError(
                "No CA found — call update_tls_certificates() at least once before "
                "adding extra names."
            )

        # Persist it first, so it isn't lost even if cert generation below fails.
        extra_names = CertificateHandler.load_extra_names()
        extra_names.add(additional_name)
        CertificateHandler.save_extra_names(extra_names)

        # Union of everything the cert should currently cover: freshly
        # discovered names/IPs, plus every extra name ever added (including
        # this new one).
        dns_names = CertificateHandler.discover_dns_names()
        ip_addresses = CertificateHandler.discover_ip_addresses()
        extra_dns_names, extra_ip_addresses = CertificateHandler.split_names_by_type(extra_names)
        dns_names |= extra_dns_names
        ip_addresses |= extra_ip_addresses

        ca_private_key = CertificateHandler.load_private_key(ca_key_path)
        ca_certificate = CertificateHandler.load_certificate(ca_cert_path)
        CertificateHandler.generate_leaf_key_and_cert(
            ca_private_key, ca_certificate, key_path, cert_path, dns_names, ip_addresses
        )

    def generate_ecc_private_key(pem_private_key_fname):
        pem_private_key_fname_temp = pem_private_key_fname+".writing"
    
        private_key = ec.generate_private_key(ec.SECP256R1())
        with open(pem_private_key_fname_temp, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        shutil.move( pem_private_key_fname_temp, pem_private_key_fname )
        os.chmod(pem_private_key_fname, stat.S_IRUSR | stat.S_IWUSR)
        return private_key

    def load_private_key(pem_private_key_fname):
        with open(pem_private_key_fname, "rb") as f:
            return serialization.load_pem_private_key(f.read(), password=None)

    def load_certificate(pem_certificate_fname):
        with open(pem_certificate_fname, "rb") as f:
            return x509.load_pem_x509_certificate(f.read())

    def generate_ca_key_and_cert(pem_private_key_fname, pem_certificate_fname):
        private_key = CertificateHandler.generate_ecc_private_key(pem_private_key_fname)

        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Pi Little Eye"),
            x509.NameAttribute(NameOID.COMMON_NAME, "Pi Little Eye Root CA"),
        ])

        now = datetime.now(timezone.utc)

        certificate = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            now
        ).not_valid_after(
            now + timedelta(days=CertificateHandler.CA_VALIDITY_DAYS)
        ).add_extension(
            x509.BasicConstraints(ca=True, path_length=0),
            critical=True,
        ).add_extension(
            x509.KeyUsage(
                digital_signature=False,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        ).add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        ).sign(private_key, hashes.SHA256())

        # Create it to a temp file and then move it over the top to make it atomic
        pem_certificate_fname_temp = pem_certificate_fname+".writing"
        with open(pem_certificate_fname_temp, "wb") as f:
            f.write(certificate.public_bytes(serialization.Encoding.PEM))
        shutil.move( pem_certificate_fname_temp, pem_certificate_fname )
        os.chmod(pem_certificate_fname, stat.S_IRUSR | stat.S_IWUSR)

        return certificate

    def generate_leaf_key_and_cert(ca_private_key, ca_certificate, pem_private_key_fname,
                                    pem_certificate_fname, dns_names, ip_addresses):
        private_key = CertificateHandler.generate_ecc_private_key(pem_private_key_fname)

        subject = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Pi Little Eye"),
            x509.NameAttribute(NameOID.COMMON_NAME, sorted(dns_names)[0]),
        ])

        san_entries = [x509.DNSName(name) for name in sorted(dns_names)]
        san_entries += [x509.IPAddress(ipaddress.ip_address(ip)) for ip in sorted(ip_addresses)]

        now = datetime.now(timezone.utc)

        certificate = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            ca_certificate.subject
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            now
        ).not_valid_after(
            now + timedelta(days=CertificateHandler.LEAF_VALIDITY_DAYS)
        ).add_extension(
            x509.SubjectAlternativeName(san_entries),
            critical=False,
        ).add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        ).add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=True,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        ).add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        ).sign(ca_private_key, hashes.SHA256())

        with open(pem_certificate_fname, "wb") as f:
            f.write(certificate.public_bytes(serialization.Encoding.PEM))
        os.chmod(pem_certificate_fname, stat.S_IRUSR | stat.S_IWUSR)

        return certificate

    def test_if_certificate_expired(pem_certificate_fname, buffer_days=0):
        cert = CertificateHandler.load_certificate(pem_certificate_fname)
        now = datetime.now(timezone.utc)
        return now + timedelta(days=buffer_days) > cert.not_valid_after_utc


    def certificate_covers_names(pem_certificate_fname, required_dns_names, required_ip_addresses):
        try:
            cert = CertificateHandler.load_certificate(pem_certificate_fname)
            san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            existing_dns = set(san.get_values_for_type(x509.DNSName))
            existing_ips = {str(ip) for ip in san.get_values_for_type(x509.IPAddress)}
        except (x509.ExtensionNotFound, Exception):
            return False

        return required_dns_names.issubset(existing_dns) and required_ip_addresses.issubset(existing_ips)
