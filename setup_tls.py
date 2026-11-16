"""Crea una CA local y certificado localhost; no instala confianza en el SO."""
from datetime import datetime, timedelta, timezone
import ipaddress
import os
import shutil
import tempfile
import uuid
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def create_certificate(directory):
    directory = Path(directory)
    if any(directory.glob('*.pem')):
        raise ValueError('Ya hay certificados; no se sobrescribieron.')
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    now = datetime.now(timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'DNSentinel CA local')])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=365))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()), critical=False)
          .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
          .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), critical=True)
          .sign(ca_key, hashes.SHA256()))
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, 'localhost')]))
            .issuer_name(ca_name).public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=90))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()), critical=False)
            .add_extension(x509.KeyUsage(True, False, True, False, False, False, False, False, False), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName('localhost'),
                x509.IPAddress(ipaddress.ip_address('127.0.0.1')),
                x509.IPAddress(ipaddress.ip_address('::1'))]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(ca_key, hashes.SHA256()))
    # La clave privada de la CA solo vive en memoria y no se guarda.
    for filename, data in [('local-ca.pem', ca.public_bytes(serialization.Encoding.PEM)),
                           ('server-cert.pem', cert.public_bytes(serialization.Encoding.PEM)),
                           ('server-key.pem', key.private_bytes(serialization.Encoding.PEM,
                            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))]:
        fd = os.open(directory / filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as file:
            file.write(data)
    return directory / 'local-ca.pem'


def upgrade_certificates(directory):
    """Generar primero; sustituir conservando los anteriores y poder deshacer un fallo."""
    directory=Path(directory)
    if not directory.exists():
        return create_certificate(directory), None
    if directory.is_symlink() or (os.name=='nt' and directory.is_junction()):
        raise ValueError('La carpeta de certificados no puede ser un enlace.')
    temporary=Path(tempfile.mkdtemp(prefix='tls-new-',dir=directory.parent))
    backup=directory.with_name(directory.name+'-backup-'+uuid.uuid4().hex[:12])
    try:
        create_certificate(temporary)
        directory.rename(backup)
        try:
            temporary.rename(directory)
        except OSError:
            backup.rename(directory)
            raise
        return directory/'local-ca.pem', backup
    finally:
        if temporary.exists():
            shutil.rmtree(temporary)


if __name__ == '__main__':
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', default='instance/tls')
    parser.add_argument('--upgrade', action='store_true', help='Renovar certificados conservando una copia privada de los anteriores. Detén primero el servidor.')
    args = parser.parse_args()
    try:
        if args.upgrade:
            ca, backup = upgrade_certificates(args.directory)
            if backup:
                print('Certificados anteriores conservados en: ' + str(backup))
        else:
            ca = create_certificate(args.directory)
    except (ValueError, OSError) as error:
        parser.exit(1, str(error) + '\n')
    print('Certificados creados. Certificado público de la CA local: ' + str(ca))
    print('Instala SOLO local-ca.pem como CA de confianza del usuario. No compartas server-key.pem.')
    print('El certificado del servidor vence en 90 días.')
