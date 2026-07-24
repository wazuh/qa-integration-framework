"""
Copyright (C) 2015-2026, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""
import hashlib
import json
import shutil
import tempfile
import threading
from queue import Queue
from typing import Dict, List, Optional
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

# Default injectable state. Tests that need to customize it (e.g. the startup-hash
# suite) overwrite these attributes on the instance before start(); they are not
# constructor parameters because almost no integration test configures them.
# NOTE: these limit values are illustrative, not confirmed manager defaults; pin them
# against the manager implementation once it lands.
DEFAULT_LIMITS = {
    'fim': {'file': 100000, 'registry_key': 100000, 'registry_value': 100000},
    'syscollector': {'packages': 50000, 'processes': 50000, 'ports': 50000},
    'sca': {'checks': 10000},
}
DEFAULT_CLUSTER = {'name': 'wazuh-cluster', 'node': 'node01'}
DEFAULT_GROUPS = ['default']
# merged.mg content whose SHA256 seeds the default config_hash. The /download endpoint
# will serve these same bytes for config resources, so the default hash matches.
DEFAULT_MERGED_MG = (
    b'#default\n'
    b'!0 agent.conf\n'
    b'<agent_config>\n'
    b'</agent_config>\n'
)


def compute_settings_hash(limits: Dict, cluster: Dict, groups: List[str]) -> str:
    """Compute the SHA256 the manager returns as ``settings_hash`` (over the startup data)."""
    payload = json.dumps({'limits': limits, 'cluster': cluster, 'groups': groups},
                         sort_keys=True).encode()
    return hashlib.sha256(payload).hexdigest()


class _RemotedRequestHandler(BaseTLSRequestHandler):
    """Route agent requests to the owning :class:`RemotedSimulator`.

    The generic HTTP/TLS mechanics live in :class:`BaseTLSRequestHandler`; this class
    only adds the Wazuh routing and per-endpoint request parsing. Response shaping
    lives on the simulator so it can be unit-tested without HTTP.
    """

    @property
    def simulator(self) -> 'RemotedSimulator':
        return self.server.context

    def do_POST(self) -> None:
        """Handle every agent request (all endpoints are POST)."""
        body = self.read_body()
        path = urlsplit(self.path).path

        self.simulator.record_request('POST', self.path, self.headers, body)

        if path == CONTROL_ENDPOINT:
            self._handle_control(body)
        elif path == CONFIG_ENDPOINT:
            self._handle_report(body, 'last_config')
        elif path == STATS_ENDPOINT:
            self._handle_report(body, 'last_stats')
        elif path in ENDPOINTS:
            # Not yet implemented in this phase; acknowledge with an empty 200.
            self.send_json(200, {})
        else:
            self.send_error_response(404, 'Not found')

    def _handle_control(self, body: bytes) -> None:
        """Dispatch a ``/control`` request on its ``type`` discriminator.

        Malformed or unrecognized control messages get a generic ``400`` (the contract
        reserves indistinguishable responses for ``401`` auth failures only).
        """
        try:
            message = json.loads(body or b'{}')
        except json.JSONDecodeError:
            self.send_error_response(400, 'Bad request')
            return

        control_type = message.get('type')
        if control_type == 'startup':
            self.send_json(200, self.simulator.startup_response())
        elif control_type == 'notify':
            self.send_json(200, self.simulator.notify_response())
        elif control_type == 'shutdown':
            self.send_json(200, self.simulator.shutdown_response())
        else:
            self.send_error_response(400, 'Bad request')

    def _handle_report(self, body: bytes, attribute: str) -> None:
        """Handle a ``/config`` or ``/stats`` push: store the JSON document, ack empty.

        Args:
            body (bytes): The request body.
            attribute (str): Simulator attribute to hold the parsed document
                (``last_config`` or ``last_stats``).
        """
        try:
            document = json.loads(body or b'{}')
        except json.JSONDecodeError:
            self.send_error_response(400, 'Bad request')
            return

        setattr(self.simulator, attribute, document)
        self.send_json(200, {})


class RemotedSimulator(BaseSimulator):
    """Simulate the manager side of the Wazuh HTTPS agent protocol.

    The agent connects as an HTTPS client and authenticates every request with an
    AES-CMAC ``Authorization`` header. This simulator stands in for ``wazuh-remoted``:
    it terminates TLS with a self-signed certificate generated at :meth:`start` and
    routes the protocol endpoints (``/control``, ``/stateless``, ``/stateful``,
    ``/download``, ``/config``, ``/stats``).

    The reusable HTTP/TLS transport lives in :mod:`wazuh_testing.tools.https_server`;
    this class holds only the Wazuh protocol behavior and the injectable server state.

    Injectable state (``limits``, ``cluster``, ``groups``, ``config_hash``,
    ``settings_hash``) is exposed as plain attributes with sensible defaults rather than
    constructor parameters; tests that need to customize it assign to these attributes
    before :meth:`start`. Response shapes follow the contract prose: startup carries no
    hash; config_hash appears in notify. The reference agent branch currently nests
    config_hash in the startup handshake too -- tracked as drift, not adopted.

    Attributes:
        MODES (list): Valid fault-injection modes for the simulator.
        limits (dict): Module limits returned by the startup response.
        cluster (dict): Cluster ``{name, node}`` returned by the startup response.
        groups (list): Agent groups returned by startup/notify responses.
        config_hash (str): SHA256 the notify response advertises for the group config.
        settings_hash (str): SHA256 the notify response advertises for the startup data.
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

        # Injectable server state (assign directly before start() to customize).
        self.limits = json.loads(json.dumps(DEFAULT_LIMITS))
        self.cluster = dict(DEFAULT_CLUSTER)
        self.groups = list(DEFAULT_GROUPS)
        self.config_hash = hashlib.sha256(DEFAULT_MERGED_MG).hexdigest()
        self.settings_hash = compute_settings_hash(self.limits, self.cluster, self.groups)

        self._tasks: List[Dict] = []
        self._tasks_lock = threading.Lock()

        # Last documents pushed by the agent (populated by /config and /stats).
        self.last_config: Optional[Dict] = None
        self.last_stats: Optional[Dict] = None

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

    def add_task(self, task: Dict) -> None:
        """Queue a manager-to-agent task to attach to the next ``notify`` response.

        Args:
            task (dict): A task object (e.g. ``{"task_id", "task_type", "payload"}``).
        """
        with self._tasks_lock:
            self._tasks.append(task)

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

    # Response builders. Pure functions of the injectable state.

    def startup_response(self) -> Dict:
        """Build the ``startup`` response body: limits, cluster and groups (no hash)."""
        return {
            'limits': self.limits,
            'cluster': self.cluster,
            'agent': {'groups': self.groups},
        }

    def notify_response(self) -> Dict:
        """Build the ``notify`` response body: hashes plus any pending tasks (drained)."""
        response = {
            'agent': {'groups': self.groups, 'config_hash': self.config_hash},
            'settings_hash': self.settings_hash,
        }
        tasks = self._drain_tasks()
        if tasks:
            response['tasks'] = tasks
        return response

    def shutdown_response(self) -> Dict:
        """Build the ``shutdown`` response body (empty acknowledgement)."""
        return {}

    # Internal methods.

    def _drain_tasks(self) -> List[Dict]:
        """Atomically return and clear the pending tasks (delivered once, locally)."""
        with self._tasks_lock:
            tasks, self._tasks = self._tasks, []
            return tasks

    @staticmethod
    def _agent_id_from_headers(headers) -> Optional[str]:
        """Extract the agent id from an ``Authorization: Wazuh <id>:<ts>:<mac>`` header."""
        authorization = headers.get('Authorization', '')
        if authorization.startswith('Wazuh '):
            credentials = authorization[len('Wazuh '):]
            return credentials.split(':', 1)[0] or None
        return None
