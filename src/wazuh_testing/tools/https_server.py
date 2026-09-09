"""
Copyright (C) 2015-2026, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

Generic, protocol-agnostic HTTP/1.1-over-TLS server building blocks.

This is the HTTPS analog of :mod:`wazuh_testing.tools.mitm`: it provides the reusable
transport machinery (a threaded TLS HTTP server, a base request handler with body
reading and response helpers, and self-signed certificate generation) that simulators
under ``tools/simulators`` compose with their own protocol logic. Nothing here knows
anything about the Wazuh wire protocol.
"""
import datetime
import ipaddress
import json
import socket
import ssl
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, Iterable, Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from zstandard import ZstdDecompressor

from wazuh_testing.tools.certificate_controller import CertificateController

DEFAULT_CA_COMMON_NAME = 'Wazuh Test Root CA'
DEFAULT_SERVER_COMMON_NAME = 'Manager'
DEFAULT_SAN_HOSTNAMES = ('localhost',)
DEFAULT_SAN_IP_ADDRESSES = ('127.0.0.1', '::1')
DEFAULT_VALID_DAYS = 3650


def generate_self_signed_certificate(dest_dir: str) -> Tuple[str, str]:
    """Generate a self-signed TLS certificate/key pair into ``dest_dir``.

    The caller owns ``dest_dir`` and is responsible for removing it.

    Deprecated in favour of :func:`generate_ca_certificate` / :func:`generate_leaf_certificate`,
    which return PEM bytes instead of paths and can express a SubjectAlternativeName. What this
    function produces is a self-signed *CA* certificate with ``CN=Manager`` and no SAN, so a client
    performing hostname verification against it always fails -- kept because that is the historical
    behaviour some callers still rely on.

    Args:
        dest_dir (str): Existing directory to write ``server.cert`` and ``server.key`` into.

    Returns:
        Tuple[str, str]: (certificate_path, key_path) as strings.
    """
    cert_path = str(Path(dest_dir) / 'server.cert')
    key_path = str(Path(dest_dir) / 'server.key')

    controller = CertificateController()
    # root_ca_cert is already self-signed by the controller (cryptography API); just persist it.
    controller.store_private_key(controller.root_ca_key, key_path)
    controller.store_ca_certificate(controller.root_ca_cert, cert_path)

    return cert_path, key_path


def _generate_private_key(key_type: str, key_size: int):
    """Generate a private key of the requested type.

    EC P-256 is the default everywhere in this module: an RSA-4096 keygen (what
    :class:`CertificateController` does) costs orders of magnitude more, and a bootstrap chain
    needs two keys rather than one.
    """
    if key_type == 'ec':
        return ec.generate_private_key(ec.SECP256R1())
    if key_type == 'rsa':
        return rsa.generate_private_key(public_exponent=65537, key_size=key_size)
    raise ValueError(f"key_type must be 'ec' or 'rsa', not {key_type!r}")


def _private_key_pem(key) -> bytes:
    """Serialise a private key as an unencrypted PEM."""
    return key.private_bytes(serialization.Encoding.PEM,
                             serialization.PrivateFormat.TraditionalOpenSSL,
                             serialization.NoEncryption())


def _validity_window(valid_days: int) -> Tuple[datetime.datetime, datetime.datetime]:
    """Return the (not_valid_before, not_valid_after) pair for a new certificate.

    Backdated by a day on purpose: a guest whose clock trails its host would otherwise be handed a
    not-yet-valid certificate, which surfaces as a confusing verification error rather than as a
    clock problem.
    """
    now = datetime.datetime.now(datetime.timezone.utc)
    return now - datetime.timedelta(days=1), now + datetime.timedelta(days=valid_days)


def _subject_alternative_name(hostnames: Iterable[str],
                              ip_addresses: Iterable[str]) -> Optional[x509.SubjectAlternativeName]:
    """Build a SubjectAlternativeName from DNS names and IP literals, or None when both are empty.

    IP entries must be ``IPAddress``, not ``DNSName``: verifying a connection to an IP literal has
    no CommonName fallback at all, so an ``iPAddress`` SAN is the only thing that can satisfy it.
    """
    entries = [x509.DNSName(hostname) for hostname in hostnames]
    entries += [x509.IPAddress(ipaddress.ip_address(address)) for address in ip_addresses]

    return x509.SubjectAlternativeName(entries) if entries else None


def generate_ca_certificate(common_name: str = DEFAULT_CA_COMMON_NAME, key_type: str = 'ec',
                            key_size: int = 2048,
                            valid_days: int = DEFAULT_VALID_DAYS) -> Tuple[bytes, bytes]:
    """Generate a self-signed signing CA, suitable as a client's sole trust anchor.

    Args:
        common_name (str): The CA's CommonName. Defaults: 'Wazuh Test Root CA'.
        key_type (str): 'ec' (P-256) or 'rsa'. Defaults: 'ec'.
        key_size (int): RSA modulus size; ignored for 'ec'. Defaults: 2048.
        valid_days (int): Lifetime in days. Defaults: 3650.

    Returns:
        Tuple[bytes, bytes]: (certificate PEM, private key PEM).
    """
    key = _generate_private_key(key_type, key_size)
    public_key = key.public_key()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    not_before, not_after = _validity_window(valid_days)
    subject_key_id = x509.SubjectKeyIdentifier.from_public_key(public_key)

    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        # path_length=0: this CA signs leaves only, never another CA.
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=False, content_commitment=False,
                                     key_encipherment=False, data_encipherment=False,
                                     key_agreement=False, key_cert_sign=True, crl_sign=True,
                                     encipher_only=False, decipher_only=False), critical=True)
        # No ExtendedKeyUsage on the CA: it constrains what the CA may issue in some verifiers,
        # and OpenSSL's own path validation does not need one.
        .add_extension(subject_key_id, critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(subject_key_id),
                       critical=False)
        .sign(key, hashes.SHA256())
    )

    return certificate.public_bytes(serialization.Encoding.PEM), _private_key_pem(key)


def generate_leaf_certificate(ca_certificate_pem: bytes, ca_key_pem: bytes,
                              common_name: str = DEFAULT_SERVER_COMMON_NAME,
                              hostnames: Iterable[str] = DEFAULT_SAN_HOSTNAMES,
                              ip_addresses: Iterable[str] = DEFAULT_SAN_IP_ADDRESSES,
                              key_type: str = 'ec', key_size: int = 2048,
                              valid_days: int = DEFAULT_VALID_DAYS) -> Tuple[bytes, bytes]:
    """Generate a TLS server certificate signed by the given CA.

    The CommonName is deliberately left as 'Manager' rather than set to the address being served:
    only the SubjectAlternativeName can then satisfy a client's hostname check, which is what makes
    a test of that check meaningful.

    Args:
        ca_certificate_pem (bytes): The issuing CA's certificate PEM.
        ca_key_pem (bytes): The issuing CA's private key PEM (unencrypted).
        common_name (str): The leaf's CommonName. Defaults: 'Manager'.
        hostnames (Iterable[str]): DNS names for the SAN. Defaults: ('localhost',).
        ip_addresses (Iterable[str]): IP literals for the SAN. Defaults: ('127.0.0.1', '::1').
        key_type (str): 'ec' (P-256) or 'rsa'. Defaults: 'ec'.
        key_size (int): RSA modulus size; ignored for 'ec'. Defaults: 2048.
        valid_days (int): Lifetime in days. Defaults: 3650.

    Returns:
        Tuple[bytes, bytes]: (certificate PEM, private key PEM).
    """
    ca_certificate = x509.load_pem_x509_certificate(ca_certificate_pem)
    ca_key = serialization.load_pem_private_key(ca_key_pem, password=None)

    key = _generate_private_key(key_type, key_size)
    public_key = key.public_key()
    not_before, not_after = _validity_window(valid_days)
    # The extension VALUE, not the Extension wrapper: from_issuer_subject_key_identifier() takes
    # the former.
    ca_subject_key_id = ca_certificate.extensions.get_extension_for_class(
        x509.SubjectKeyIdentifier).value

    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)]))
        .issuer_name(ca_certificate.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        # key_encipherment matters only for RSA key transport (TLS <= 1.2) and is harmless under
        # 1.3; key_agreement stays off, since ECDHE signs with this certificate rather than
        # performing a keyAgreement with it.
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                     key_encipherment=True, data_encipherment=False,
                                     key_agreement=False, key_cert_sign=False, crl_sign=False,
                                     encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
            ca_subject_key_id), critical=False)
    )

    subject_alternative_name = _subject_alternative_name(hostnames, ip_addresses)
    if subject_alternative_name is not None:
        builder = builder.add_extension(subject_alternative_name, critical=False)

    certificate = builder.sign(ca_key, hashes.SHA256())

    return certificate.public_bytes(serialization.Encoding.PEM), _private_key_pem(key)


def write_pem_pair(dest_dir: str, certificate_pem: bytes, key_pem: bytes,
                   certificate_name: str = 'server.cert',
                   key_name: str = 'server.key') -> Tuple[str, str]:
    """Persist a (certificate, key) PEM pair into ``dest_dir``.

    Args:
        dest_dir (str): Existing directory to write into.
        certificate_pem (bytes): The certificate PEM.
        key_pem (bytes): The private key PEM.
        certificate_name (str): Certificate filename. Defaults: 'server.cert'.
        key_name (str): Key filename. Defaults: 'server.key'.

    Returns:
        Tuple[str, str]: (certificate_path, key_path) as strings.
    """
    certificate_path = Path(dest_dir) / certificate_name
    key_path = Path(dest_dir) / key_name
    certificate_path.write_bytes(certificate_pem)
    key_path.write_bytes(key_pem)

    return str(certificate_path), str(key_path)


class TLSHTTPServer(ThreadingHTTPServer):
    """A threaded HTTP/1.1 server whose listening socket is wrapped in TLS.

    Protocol-agnostic: it terminates TLS and dispatches every connection (in its own
    thread) to ``handler_class``. Callers attach arbitrary state through ``context``,
    which handlers reach via ``self.server.context``.

    Attributes:
        context: Arbitrary caller-provided state (e.g. the owning simulator).
    """

    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, server_address: Tuple[str, int], handler_class,
                 certfile: str, keyfile: str, client_ca_cert: Optional[str] = None,
                 context=None) -> None:
        """Bind, wrap the listening socket in TLS, and store the caller context.

        Args:
            server_address (Tuple[str, int]): (host, port) to bind to.
            handler_class: A BaseHTTPRequestHandler subclass.
            certfile (str): Path to the TLS server certificate (PEM).
            keyfile (str): Path to the TLS server private key (PEM).
            client_ca_cert (str, optional): Path to a CA certificate (PEM). When given,
                every client on this listener must present a certificate signed by this CA
                -- the TLS handshake itself fails otherwise (mutual TLS), before any HTTP
                request is ever read. Defaults: None (no client certificate required).
            context: Arbitrary state exposed to handlers via ``self.server.context``.
        """
        # ThreadingHTTPServer defaults to AF_INET; binding an IPv6 literal against it
        # fails with "Address family for hostname not supported" (EAI_ADDRFAMILY), not
        # a clearer error, so detect it up front the same way every other IPv6-literal
        # check in this codebase does.
        if ':' in server_address[0]:
            self.address_family = socket.AF_INET6
        super().__init__(server_address, handler_class)
        self.context = context

        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(certfile=certfile, keyfile=keyfile)
        if client_ca_cert:
            ssl_context.verify_mode = ssl.CERT_REQUIRED
            ssl_context.load_verify_locations(cafile=client_ca_cert)
        self.socket = ssl_context.wrap_socket(self.socket, server_side=True)

    def handle_error(self, request, client_address) -> None:
        """Swallow expected transport noise; surface genuine handler bugs.

        A plain-HTTP probe on the TLS port or a client disconnect is expected and
        silenced. Anything else is a real error and is delegated to the stdlib
        handler (which prints a traceback) so it is not hidden.
        """
        exc = sys.exc_info()[1]
        if isinstance(exc, (ssl.SSLError, ConnectionResetError, BrokenPipeError, socket.timeout)):
            return
        super().handle_error(request, client_address)


class BaseTLSRequestHandler(BaseHTTPRequestHandler):
    """HTTP/1.1 request handler with body-reading and response helpers.

    Protocol-agnostic base for :class:`TLSHTTPServer`. Subclasses implement the
    ``do_*`` verb methods and use the helpers below to read the request body and send
    JSON or error responses.
    """

    # HTTP/1.1 enables persistent connections and requires a Content-Length or
    # chunked framing on every response (the helpers below always send one).
    protocol_version = 'HTTP/1.1'

    def log_message(self, format: str, *args) -> None:
        """Silence the default stderr access log."""
        pass

    def read_body(self) -> bytes:
        """Read the exact request body bytes (Content-Length or chunked)."""
        if self.headers.get('Transfer-Encoding', '').lower() == 'chunked':
            return self._read_chunked_body()

        length = self.headers.get('Content-Length')
        if length is None:
            return b''
        return self.rfile.read(int(length))

    def decode_body(self, body: bytes) -> Tuple[bytes, Optional[Tuple[int, str]]]:
        """Undo the request's ``Content-Encoding``, if it has one.

        Args:
            body (bytes): The raw request body, exactly as read off the socket.

        Returns:
            Tuple[bytes, Optional[Tuple[int, str]]]: ``(decoded, error)``. ``error`` is
            None on success. Otherwise it is the ``(status, message)`` pair the caller
            should answer with, and ``decoded`` is the untouched input.

        An encoding this server cannot undo is a 415, because that is what a server
        without support answers and clients are expected to retry uncompressed. A body
        that claims ``zstd`` but fails to decode is a 400 instead: the encoding was
        understood, the payload was simply broken.
        """
        encoding = self.headers.get('Content-Encoding', '').strip().lower()

        if not encoding or encoding == 'identity':
            return body, None

        if encoding != 'zstd':
            return body, (415, f'Unsupported Content-Encoding: {encoding}')

        try:
            # decompressobj() rather than decompress(): a frame whose header carries no
            # pledged content size (what the streaming compressor emits) still decodes.
            return ZstdDecompressor().decompressobj().decompress(body), None
        except Exception:
            return body, (400, 'Malformed zstd body')

    def _read_chunked_body(self) -> bytes:
        """De-chunk an HTTP/1.1 ``Transfer-Encoding: chunked`` body."""
        body = bytearray()
        while True:
            size_line = self.rfile.readline().strip()
            if not size_line:
                continue
            chunk_size = int(size_line.split(b';', 1)[0], 16)
            if chunk_size == 0:
                self.rfile.readline()  # Consume the trailing CRLF after the last chunk.
                break
            body.extend(self.rfile.read(chunk_size))
            self.rfile.readline()  # Consume the CRLF after each chunk.
        return bytes(body)

    def send_body(self, data: bytes, status: int = 200,
                  content_type: str = 'application/octet-stream',
                  extra_headers: Dict = None, close_connection: bool = False) -> None:
        """Send an exact byte body with a chosen ``Content-Type`` and a ``Content-Length``.

        Content-Length rather than chunked framing, unlike :meth:`send_chunked`: it is what a
        response whose body is already fully in hand should use, and it keeps a byte-exactness
        assertion in a test free of de-chunking.

        Args:
            data (bytes): The body, sent verbatim.
            status (int): HTTP status code. Defaults: 200.
            content_type (str): Response Content-Type. Defaults: application/octet-stream.
            extra_headers (Dict, optional): Additional response headers.
            close_connection (bool): Send ``Connection: close`` and drop the connection after
                this response. Defaults: False.
        """
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Length', str(len(data)))
        for name, value in (extra_headers or {}).items():
            self.send_header(name, str(value))
        if close_connection:
            self.send_header('Connection', 'close')
            self.close_connection = True
        self.end_headers()
        self.wfile.write(data)

    def send_json(self, status: int, payload: Dict, extra_headers: Dict = None) -> None:
        """Send a JSON response with the given status code and optional extra headers."""
        self.send_body(json.dumps(payload).encode(), status, 'application/json',
                       extra_headers=extra_headers)

    def send_empty(self, status: int = 200) -> None:
        """Send a response with the given status code and an empty body."""
        self.send_response(status)
        self.send_header('Content-Length', '0')
        self.end_headers()

    def send_chunked(self, data: bytes, status: int = 200,
                     content_type: str = 'application/octet-stream',
                     chunk_size: int = 65536) -> None:
        """Send a body using HTTP/1.1 ``Transfer-Encoding: chunked``.

        Args:
            data (bytes): The full payload to stream.
            status (int): HTTP status code. Defaults: 200.
            content_type (str): Response Content-Type. Defaults: application/octet-stream.
            chunk_size (int): Bytes per chunk. Defaults: 65536 (64 KB).
        """
        self.send_response(status)
        self.send_header('Content-Type', content_type)
        self.send_header('Transfer-Encoding', 'chunked')
        self.end_headers()

        for offset in range(0, len(data), chunk_size):
            chunk = data[offset:offset + chunk_size]
            self.wfile.write(f'{len(chunk):x}\r\n'.encode() + chunk + b'\r\n')
        self.wfile.write(b'0\r\n\r\n')

    def send_error_response(self, status: int, message: str, extra_headers: Dict = None) -> None:
        """Send a generic ``{"error", "code"}`` JSON error envelope."""
        self.send_json(status, {'error': message, 'code': status}, extra_headers=extra_headers)
