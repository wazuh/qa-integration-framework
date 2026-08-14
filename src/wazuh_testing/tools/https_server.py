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
import json
import socket
import ssl
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Dict, Tuple

from wazuh_testing.tools.certificate_controller import CertificateController


def generate_self_signed_certificate(dest_dir: str) -> Tuple[str, str]:
    """Generate a self-signed TLS certificate/key pair into ``dest_dir``.

    The caller owns ``dest_dir`` and is responsible for removing it.

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
                 certfile: str, keyfile: str, context=None) -> None:
        """Bind, wrap the listening socket in TLS, and store the caller context.

        Args:
            server_address (Tuple[str, int]): (host, port) to bind to.
            handler_class: A BaseHTTPRequestHandler subclass.
            certfile (str): Path to the TLS server certificate (PEM).
            keyfile (str): Path to the TLS server private key (PEM).
            context: Arbitrary state exposed to handlers via ``self.server.context``.
        """
        super().__init__(server_address, handler_class)
        self.context = context

        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(certfile=certfile, keyfile=keyfile)
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

    def send_json(self, status: int, payload: Dict, extra_headers: Dict = None) -> None:
        """Send a JSON response with the given status code and optional extra headers."""
        data = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        for name, value in (extra_headers or {}).items():
            self.send_header(name, str(value))
        self.end_headers()
        self.wfile.write(data)

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
