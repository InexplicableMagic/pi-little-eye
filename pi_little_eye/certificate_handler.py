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
from .db_config_handler import DBConfigHandler

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

    def get_ca_cert_file_path():
        return os.path.join(CertificateHandler.CERTIFICATES_DIR, CertificateHandler.CA_CERTIFICATE_FNAME)

    def get_ca_key_file_path():
        return os.path.join(CertificateHandler.CERTIFICATES_DIR, CertificateHandler.CA_PRIVATE_KEY_FNAME)

    def get_cert_file_path():
        return os.path.join(CertificateHandler.CERTIFICATES_DIR, CertificateHandler.CERTIFICATE_FNAME)

    def get_key_file_path():
        return os.path.join(CertificateHandler.CERTIFICATES_DIR, CertificateHandler.PRIVATE_KEY_FNAME)

    # Adds a certificate/key if missing or expired
    # 
    # regenerate_cert = True, forces regeneration of the server certificate and key regardless of expiry
    # regenerate_ca = True forces a regeneration of the certificate authority and key regardless of expiry
    def update_tls_certificates(dbch, regenerate_cert = False, regenerate_ca = False):
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
        if not os.path.exists(ca_cert_path) or not os.path.exists(ca_key_path):
            regenerate_ca = True
        elif CertificateHandler.test_if_certificate_expired(ca_cert_path):
            regenerate_ca = True

        if regenerate_ca:
            CertificateHandler.generate_ca_key_and_cert(ca_key_path, ca_cert_path)

        san_names = dbch.get_all_san_names()
        # Need at least one name on the SAN list to make a valid certificate
        if len(san_names) < 1:
            dns_names = { 'localhost' }
            ip_addresses = set()
        else:
            dns_names, ip_addresses = CertificateHandler.split_names_by_type( san_names )

        leaf_needs_reissue = (
            regenerate_ca
            or regenerate_cert
            or not os.path.exists(cert_path)
            or not os.path.exists(key_path)
            or CertificateHandler.test_if_certificate_expired(cert_path, buffer_days=CertificateHandler.LEAF_RENEWAL_BUFFER_DAYS)
        )

        if leaf_needs_reissue:
            ca_private_key = CertificateHandler.load_private_key(ca_key_path)
            ca_certificate = CertificateHandler.load_certificate(ca_cert_path)
            CertificateHandler.generate_leaf_key_and_cert(
                ca_private_key, ca_certificate, key_path, cert_path, dns_names, ip_addresses
            )

            dbch.save_all_san_names( list(dns_names | ip_addresses) )

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

    def add_dns_name_to_certificate(dbch, additional_name):
        if DBConfigHandler.validate_utf8_string(additional_name, min_length=1, max_length=253):
            san_names = dbch.get_all_san_names()
            san_names.append( additional_name )
            san_names = list(set(san_names))
            dbch.save_all_san_names( san_names )
            CertificateHandler.update_tls_certificates(dbch, regenerate_cert = True)        

    def generate_ecc_private_key(pem_private_key_fname):
        pem_private_key_fname_temp = pem_private_key_fname+".writing"
    
        # Elliptic curve should be better for slower CPU devices like the Pi
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

