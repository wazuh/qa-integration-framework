import os
import platform
import random
import stat

from OpenSSL import crypto

if platform.system() == 'Windows':
    import win32api
    import win32con


class CertificateController:
    def __init__(self, message_digest: str = 'sha256WithRSAEncryption'):
        self.root_ca_key = crypto.PKey()
        self.root_ca_key.generate_key(crypto.TYPE_RSA, 4096)
        self.root_ca_cert = self._create_ca_cert(self.root_ca_key)
        self.digest = message_digest

    def generate_agent_certificates(self, agent_key_path: str, agent_cert_path: str, agentname: str,
                                    key_bits: int = 4096, signed: bool = True) -> None:
        key = crypto.PKey().generate_key(crypto.TYPE_RSA, key_bits)
        self._add_key_to_certificate(key)
        cert = self._create_ca_cert(key, subject=agentname)

        if signed:
            cert.sign(self.root_ca_key, self.digest)
        else:
            cert.sign(key, self.digest)

        self.store_private_key(key, agent_key_path)
        self.store_ca_certificate(cert, agent_cert_path)

    def _create_ca_cert(self, pub_key: crypto.PKey, issuer: str = "Manager", subject: str = None,
                        version: int = 2, expiration_time: int = 0) -> crypto.X509:
        cert = crypto.X509()
        cert.set_serial_number(random.randint(500000, 1000000))
        cert.set_version(version)
        cert.get_subject().CN = subject or issuer
        cert.gmtime_adj_notBefore(0)
        cert.gmtime_adj_notAfter(expiration_time if expiration_time else 10 * 365 * 24 * 60 * 60)
        cert.set_issuer(cert.get_subject())
        cert.set_pubkey(pub_key)
        cert.add_extensions([
            crypto.X509Extension(b'basicConstraints', True, b'CA:TRUE, pathlen:0'),
            crypto.X509Extension(b'keyUsage', True, b'keyCertSign, cRLSign'),
            crypto.X509Extension(b'subjectKeyIdentifier', False, b'hash', subject=cert),
        ])
        cert.sign(self.root_ca_key, self.digest)
        return cert

    @staticmethod
    def store_private_key(key: crypto.PKey, path: str) -> None:
        with open(path, 'wb') as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
        if platform.system() != 'Windows':
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)

    @staticmethod
    def store_ca_certificate(cert: crypto.X509, path: str) -> None:
        with open(path, 'wb') as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
