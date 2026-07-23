"""
Copyright (C) 2015-2026, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""
import shutil
import tempfile
import threading
from queue import Queue
from typing import Optional
from urllib.parse import urlsplit

from wazuh_testing.constants.paths.configurations import WAZUH_CLIENT_KEYS_PATH
from wazuh_testing.tools.https_server import (BaseTLSRequestHandler, TLSHTTPServer,
                                              generate_self_signed_certificate)

from .base_simulator import BaseSimulator


# The manager-side endpoints the HTTPS agent talks to.
CONTROL_ENDPOINT = '/control'
STATELESS_ENDPOINT = '/stateless'
STATEFUL_ENDPOINT = '/stateful'
DOWNLOAD_ENDPOINT = '/download'
CONFIG_ENDPOINT = '/config'
STATS_ENDPOINT = '/stats'

ENDPOINTS = (
    CONTROL_ENDPOINT,
    STATELESS_ENDPOINT,
    STATEFUL_ENDPOINT,
    DOWNLOAD_ENDPOINT,
    CONFIG_ENDPOINT,
    STATS_ENDPOINT,
)


class _RemotedRequestHandler(BaseTLSRequestHandler):
    """Route agent requests to the owning :class:`RemotedSimulator`.

    The generic HTTP/TLS mechanics live in :class:`BaseTLSRequestHandler`; this class
    only adds the Wazuh routing. Phase 1 records the request and answers with an empty
    ``200`` for the known endpoints; endpoint bodies, auth and fault modes are layered
    on top in later phases.
    """

    @property
    def simulator(self) -> 'RemotedSimulator':
        return self.server.context

    def do_POST(self) -> None:
        """Handle every agent request (all endpoints are POST)."""
        body = self.read_body()
        path = urlsplit(self.path).path

        self.simulator.record_request('POST', self.path, self.headers, body)

        if path in ENDPOINTS:
            # Phase 1 stub: acknowledge with an empty JSON object.
            self.send_json(200, {})
        else:
            self.send_error_response(404, 'Not found')


class RemotedSimulator(BaseSimulator):
    """Simulate the manager side of the Wazuh HTTPS agent protocol.

    The agent (initiative #37702) connects as an HTTPS client and authenticates every
    request with an AES-CMAC ``Authorization`` header. This simulator stands in for
    ``wazuh-remoted``: it terminates TLS with a self-signed certificate generated at
    :meth:`start` and routes the protocol endpoints (``/control``, ``/stateless``,
    ``/stateful``, ``/download``, ``/config``, ``/stats``).

    The reusable HTTP/TLS transport lives in :mod:`wazuh_testing.tools.https_server`;
    this class holds only the Wazuh protocol behavior.

    Attributes:
        MODES (list): Valid fault-injection modes for the simulator.
        server_ip (str): Address the TLS server binds to.
        port (int): Port the TLS server binds to.
        keys_path (str): Path to the client.keys file used to resolve agent keys.
    """

    MODES = ['ACCEPT', 'REJECT_AUTH', 'BAD_REQUEST', 'SERVICE_UNAVAILABLE', 'PAYLOAD_TOO_LARGE']

    def __init__(self,
                 server_ip: str = '127.0.0.1',
                 port: int = 1514,
                 mode: str = 'ACCEPT',
                 keys_path: str = WAZUH_CLIENT_KEYS_PATH) -> None:
        """Initialize a RemotedSimulator.

        Args:
            server_ip (str, optional): Address to bind the TLS server to. Defaults: '127.0.0.1'.
            port (int, optional): Port to bind the TLS server to. Defaults: 1514.
            mode (str, optional): Fault-injection mode. Must be one of MODES. Defaults: 'ACCEPT'.
            keys_path (str, optional): Path to the client.keys file. Defaults: WAZUH_CLIENT_KEYS_PATH.
        """
        super().__init__(server_ip, port, False)

        self.mode = mode
        self.keys_path = keys_path

        self._queue: Queue = Queue()
        self._httpd: Optional[TLSHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._cert_dir: Optional[str] = None

    # Properties.

    @property
    def queue(self) -> Queue:
        """Queue of received requests, each a dict with method/path/headers/body/agent_id."""
        return self._queue

    # Methods.

    def start(self) -> None:
        """Start the TLS HTTP server in a background thread."""
        if self.running:
            return

        self._cert_dir = tempfile.mkdtemp(prefix='remoted_simulator_')
        cert_path, key_path = generate_self_signed_certificate(self._cert_dir)

        self._httpd = TLSHTTPServer((self.server_ip, self.port), _RemotedRequestHandler,
                                    certfile=cert_path, keyfile=key_path, context=self)

        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()
        self.running = True

    def shutdown(self) -> None:
        """Stop the TLS HTTP server and clean up the temporary certificate."""
        if not self.running:
            return

        self._httpd.shutdown()
        self._thread.join()
        self._httpd.server_close()
        self.running = False

        if self._cert_dir:
            shutil.rmtree(self._cert_dir, ignore_errors=True)
            self._cert_dir = None

    def clear(self) -> None:
        """Remove all recorded requests from the queue."""
        while not self._queue.empty():
            self._queue.get_nowait()

    def destroy(self) -> None:
        """Clear the queue and shut the simulator down."""
        self.clear()
        self.shutdown()

    def record_request(self, method: str, path: str, headers, body: bytes) -> None:
        """Store a received request for later assertions.

        Args:
            method (str): HTTP method of the request.
            path (str): Raw request target (path plus query string).
            headers: The request headers (email.message.Message).
            body (bytes): Exact request body bytes.
        """
        self._queue.put({
            'method': method,
            'path': path,
            'headers': dict(headers.items()),
            'agent_id': self._agent_id_from_headers(headers),
            'body': body,
        })

    # Internal methods.

    @staticmethod
    def _agent_id_from_headers(headers) -> Optional[str]:
        """Extract the agent id from an ``Authorization: Wazuh <id>:<ts>:<mac>`` header."""
        authorization = headers.get('Authorization', '')
        if authorization.startswith('Wazuh '):
            credentials = authorization[len('Wazuh '):]
            return credentials.split(':', 1)[0] or None
        return None
