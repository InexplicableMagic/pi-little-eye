import socket
import os
import stat

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta

class CertificateHandler:

    CERTIFICATES_DIR = "certificates"
    CERTIFICATE_FNAME = "certfile.pem"
    PRIVATE_KEY_FNAME = "key.pem"

    # Generate a self-sign certificate and key if either it doesn't exist it it's expired
    
    def get_cert_file_path():
        return os.path.join( CertificateHandler.CERTIFICATES_DIR, CertificateHandler. CERTIFICATE_FNAME)
        
    def get_key_file_path():
        return os.path.join( CertificateHandler.CERTIFICATES_DIR, CertificateHandler. PRIVATE_KEY_FNAME)
    
    def update_tls_certificates():
        if not os.path.exists(CertificateHandler.CERTIFICATES_DIR):
            os.makedirs(CertificateHandler.CERTIFICATES_DIR)
            os.chmod(CertificateHandler.CERTIFICATES_DIR, stat.S_IRWXU)
        
        cert_file_path = CertificateHandler.get_cert_file_path()
        key_file_path = CertificateHandler.get_key_file_path()
        
        if not os.path.exists(cert_file_path) or not os.path.exists(key_file_path):
            CertificateHandler.GenerateCertificateWithKey( key_file_path, cert_file_path )
        else:
            if CertificateHandler.test_if_certificate_expired( cert_file_path ):
                CertificateHandler.GenerateCertificateWithKey( key_file_path, cert_file_path )
        
    def GenerateCertificateWithKey( pem_private_key_fname, pem_certificate_fname ):
        private_key = CertificateHandler.generate_ecc_private_key( pem_private_key_fname )
        CertificateHandler.generate_ecc_certificate( private_key, pem_certificate_fname )      
    
    # Generate a 256-bit elliptic curve private key
    def generate_ecc_private_key( pem_private_key_fname ):
        private_key = ec.generate_private_key(ec.SECP256R1())

        # Write private key to PEM file
        with open(pem_private_key_fname, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
        ))
        
        os.chmod(pem_private_key_fname, stat.S_IRUSR | stat.S_IWUSR)
       
        return private_key
    
    # Generate a elliptic curve certificate using the key
    def generate_ecc_certificate( private_key, pem_certificate_fname ):
        
        subject = issuer = x509.Name([
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Raspberry Pi Security Camera"),
            x509.NameAttribute(NameOID.COMMON_NAME, u"localhost"),
        ])

        # Build self-signed certificate
        certificate = x509.CertificateBuilder().subject_name(
            subject
        ).issuer_name(
            issuer
        ).public_key(
            private_key.public_key()
        ).serial_number(
            x509.random_serial_number()
        ).not_valid_before(
            datetime.utcnow()
        ).not_valid_after(
            datetime.utcnow() + timedelta(days=365)
        ).add_extension(
            x509.SubjectAlternativeName([
                x509.DNSName(u"localhost")
            ]),
            critical=False,
        ).sign(private_key, hashes.SHA256())

        # Write certificate to PEM file
        with open(pem_certificate_fname, "wb") as f:
            f.write(certificate.public_bytes(serialization.Encoding.PEM))
        
        os.chmod(pem_certificate_fname, stat.S_IRUSR | stat.S_IWUSR)
            
    def test_if_certificate_expired( pem_certificate_fname ):
    
        with open(pem_certificate_fname, "rb") as f:
            cert_data = f.read()
            cert = x509.load_pem_x509_certificate(cert_data, default_backend())

        # Check if the certificate has expired
        now = datetime.utcnow()
        return now > cert.not_valid_after
        
        
        

