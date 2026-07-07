# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import datetime
import os
import platform
import stat

from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID

if platform.system() == 'Windows':
    import win32api
    import win32con


class CertificateController:
    """A class for generating and storing certificates and private keys."""

    def __init__(self, message_digest: str = 'sha256WithRSAEncryption'):
        """
        Initialize a CertificateController instance.

        Args:
            message_digest (str): The message digest algorithm to use. Defaults to 'sha256WithRSAEncryption'.
        """

        self.digest = message_digest
        self.root_ca_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        self.root_ca_cert = self._create_ca_cert(self.root_ca_key)

    def get_root_ca_cert(self):
        return self.root_ca_cert

    def get_root_ca_key(self):
        return self.root_ca_key

    def generate_agent_certificates(self, agent_key_path: str, agent_cert_path: str, agentname: str,
                                    key_bits: int = 4096, signed: bool = True) -> None:
        """
        Generate agent certificates and store them in the specified paths.

        Args:
            agent_key_path (str): The path to store the agent's private key.
            agent_cert_path (str): The path to store the agent's certificate.
            agentname (str): The name of the agent.
            key_bits (int): The number of bits for the RSA key. Defaults to 4096.
            signed (bool): Whether to sign the certificate with the root CA key. Defaults to True.
        """
        key = rsa.generate_private_key(public_exponent=65537, key_size=key_bits)

        signing_key = self.root_ca_key if signed else key
        cert = self._create_ca_cert(key, subject=agentname, signing_key=signing_key)

        self.store_private_key(key, agent_key_path)
        self.store_ca_certificate(cert, agent_cert_path)

    def _create_ca_cert(self, pub_key: rsa.RSAPrivateKey, issuer: str = "Manager", subject: str = None,
                        expiration_time: int = 0, signing_key: rsa.RSAPrivateKey = None) -> x509.Certificate:
        """
        Create a CA certificate using the provided public key.

        Args:
            pub_key (rsa.RSAPrivateKey): The public key for the certificate.
            issuer (str): The issuer of the certificate. Defaults to "Manager".
            subject (str): The subject of the certificate. If not provided, the issuer is used.
            expiration_time (int): The expiration time of the certificate in seconds.
                If not provided, it defaults to 10 years.
            signing_key (rsa.RSAPrivateKey): The key used to sign the certificate.
                If not provided, the root CA key is used.

        Returns:
            x509.Certificate: The created CA certificate.
        """
        public_key = pub_key.public_key()

        expiry = expiration_time if expiration_time else 10 * 365 * 24 * 60 * 60
        now = datetime.datetime.now(datetime.timezone.utc)

        builder = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject or issuer)]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer)]))
            .public_key(public_key)
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(seconds=expiry))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        )

        signer = signing_key or self.root_ca_key
        cryptography_cert = builder.sign(signer, hashes.SHA256())

        return cryptography_cert

    @staticmethod
    def store_private_key(key: rsa.RSAPrivateKey, path: str) -> None:
        """
        Store a private key in the specified path.

        Args:
            key (rsa.RSAPrivateKey): The private key to store.
            path (str): The path to store the private key.
        """
        with open(path, 'wb') as f:
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        if platform.system() != 'Windows':
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)

    @staticmethod
    def store_ca_certificate(cert: x509.Certificate, path: str) -> None:
        """
        Store a CA certificate in the specified path.

        Args:
            cert (x509.Certificate): The CA certificate to store.
            path (str): The path to store the CA certificate.
        """
        with open(path, 'wb') as f:
            f.write(cert.public_bytes(serialization.Encoding.PEM))
