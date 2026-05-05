# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import datetime
import os
import platform
import random
import stat

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from OpenSSL import crypto

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
        self.root_ca_key = crypto.PKey()
        self.root_ca_key.generate_key(crypto.TYPE_RSA, 4096)
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
        key = crypto.PKey()
        key.generate_key(crypto.TYPE_RSA, key_bits)
        cert = self._create_ca_cert(key, subject=agentname)

        if signed:
            cert.sign(self.root_ca_key, self.digest)
        else:
            cert.sign(key, self.digest)

        self.store_private_key(key, agent_key_path)
        self.store_ca_certificate(cert, agent_cert_path)

    def _create_ca_cert(self, pub_key: crypto.PKey, issuer: str = "Manager", subject: str = None,
                        version: int = 2, expiration_time: int = 0) -> crypto.X509:
        """
        Create a CA certificate using the provided public key.

        Args:
            pub_key (crypto.PKey): The public key for the certificate.
            issuer (str): The issuer of the certificate. Defaults to "Manager".
            subject (str): The subject of the certificate. If not provided, the issuer is used.
            version (int): The version number of the certificate. Defaults to 2.
            expiration_time (int): The expiration time of the certificate in seconds.
                If not provided, it defaults to 10 years.

        Returns:
            crypto.X509: The created CA certificate.
        """
        crypto_key = pub_key.to_cryptography_key()
        if hasattr(crypto_key, 'public_key'):
            public_key = crypto_key.public_key()
        else:
            public_key = crypto_key

        expiry = expiration_time if expiration_time else 10 * 365 * 24 * 60 * 60
        now = datetime.datetime.now(datetime.timezone.utc)

        builder = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject or issuer)]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer)]))
            .public_key(public_key)
            .serial_number(random.randint(500000, 1000000))
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(seconds=expiry))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        )
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False
        )

        signing_key = self.root_ca_key.to_cryptography_key()
        cryptography_cert = builder.sign(signing_key, hashes.SHA256())

        return crypto.X509.from_cryptography(cryptography_cert)

    @staticmethod
    def store_private_key(key: crypto.PKey, path: str) -> None:
        """
        Store a private key in the specified path.

        Args:
            key (crypto.PKey): The private key to store.
            path (str): The path to store the private key.
        """
        with open(path, 'wb') as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
        if platform.system() != 'Windows':
            os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)

    @staticmethod
    def store_ca_certificate(cert: crypto.X509, path: str) -> None:
        """
        Store a CA certificate in the specified path.

        Args:
            cert (crypto.X509): The CA certificate to store.
            path (str): The path to store the CA certificate.
        """
        with open(path, 'wb') as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))
