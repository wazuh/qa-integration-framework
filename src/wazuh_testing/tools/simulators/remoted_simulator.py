"""
Copyright (C) 2015-2026, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

RemotedSimulator: a TLS HTTP/1.1 stand-in for the manager side of the Wazuh HTTPS agent
protocol (/control, /stateless, /stateful, /download, /config, /stats).

Quickstart in a test:

    sim = RemotedSimulator(port=1517)
    sim.add_task({'task_id': 't1', 'task_type': 'agent_restart', 'payload': {}})  # rides next notify
    sim.start()
    try:
        run_agent()                                       # agent drives /control startup + notifies
        assert sim.last_request('/control')['agent_id'] == '001'   # assert what the agent sent
    finally:
        sim.destroy()

The manager responses are deterministic and inspectable without an agent -- e.g. the reply the
simulator returns for a /control startup:

    sim.startup_response()   # {'limits': {...}, 'cluster': {...}, 'agent': {'groups': [...]}}

(notify_response() also returns settings_hash/config_hash and delivers any queued tasks once.)

- Faults: RemotedSimulator(mode='REJECT_AUTH') or sim.mode = 'SERVICE_UNAVAILABLE'.
- Traffic: sim.requests / sim.get_requests(path) / sim.last_request(path).
- State: set limits/cluster/groups/config_hash/merged_mg/wpk before start()
  (settings_hash is derived from the startup response).
"""
import hashlib
import hmac
import json
import shutil
import tempfile
import threading
import time
from typing import Dict, List, Optional
from urllib.parse import urlsplit

from wazuh_testing.constants.paths.configurations import WAZUH_CLIENT_KEYS_PATH
from wazuh_testing.constants.ports import DEFAULT_HTTPS_REMOTE_CONNECTION_PORT
from wazuh_testing.tools.https_server import (BaseTLSRequestHandler, TLSHTTPServer,
                                              generate_self_signed_certificate)
from wazuh_testing.utils import request_auth
from wazuh_testing.utils.client_keys import get_client_keys

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

# Seconds advertised in the Retry-After header of the SERVICE_UNAVAILABLE (503) fault mode.
RETRY_AFTER_SECONDS = 5


def parse_he_batch(body: bytes):
    """Parse a ``/stateless`` H/E event batch into its header metadata and events.

    The batch is a single ``H <json-metadata>`` line followed by one or more
    ``E <queue>:<location>:<message>`` events. Events are separated by the byte
    sequence ``\\nE`` followed by a space; continuation lines inside an event carry an
    extra leading space, so they are not mistaken for a new event.

    Args:
        body (bytes): The raw request body.

    Returns:
        Tuple[dict, List[bytes]]: The parsed H metadata and the list of event payloads.

    Raises:
        ValueError: If the H header is missing, there are no events, or the H metadata
            is not valid JSON.
    """
    if not body.startswith(b'H '):
        raise ValueError('missing H header')

    segments = body.split(b'\nE ')
    header, events = segments[0][len(b'H '):], segments[1:]

    if not events:
        raise ValueError('no events')

    try:
        metadata = json.loads(header)
    except json.JSONDecodeError as error:
        raise ValueError('invalid H metadata') from error

    return metadata, events


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
        self._authenticated_agent_id = None

        self.simulator.record_request('POST', self.path, self.headers, body)

        if self._inject_fault():
            return

        if not self._verify_auth(body):
            return

        if path == CONTROL_ENDPOINT:
            self._handle_control(body)
        elif path == STATELESS_ENDPOINT:
            self._handle_stateless(body)
        elif path == STATEFUL_ENDPOINT:
            self._handle_stateful(body)
        elif path == CONFIG_ENDPOINT:
            self._handle_report(body, 'last_config')
        elif path == STATS_ENDPOINT:
            self._handle_report(body, 'last_stats')
        elif path == DOWNLOAD_ENDPOINT:
            self._handle_download(body)
        elif path in ENDPOINTS:
            # Not yet implemented in this phase; acknowledge with an empty 200.
            self.send_json(200, {})
        else:
            self.send_error_response(404, 'Not found')

    def _inject_fault(self) -> bool:
        """Apply the simulator's fault-injection mode before normal routing.

        Returns True (having sent the fault response) for every mode except ``ACCEPT``,
        so the caller skips endpoint handling. The generic ``401`` never distinguishes
        its cause, per the auth contract.
        """
        mode = self.simulator.mode
        if mode == 'ACCEPT':
            return False

        if mode == 'REJECT_AUTH':
            self.send_error_response(401, 'Invalid client authentication')
        elif mode == 'BAD_REQUEST':
            self.send_error_response(400, 'Bad request')
        elif mode == 'SERVICE_UNAVAILABLE':
            self.send_error_response(503, 'Service temporarily unavailable',
                                     extra_headers={'Retry-After': RETRY_AFTER_SECONDS})
        elif mode == 'PAYLOAD_TOO_LARGE':
            self.send_error_response(413, 'Request payload is too large')
        return True

    def _verify_auth(self, body: bytes) -> bool:
        """Verify the AES-CMAC Authorization header when verification is enabled.

        Returns True if the request is authenticated (or verification is off). On any
        failure it sends a single generic ``401`` (never distinguishing the cause) and
        returns False so the caller skips endpoint handling. On success it records the
        authenticated agent id for later identity binding.
        """
        if not self.simulator.verify_auth:
            return True

        if self.headers.get('protocol-version') != request_auth.PROTOCOL_VERSION:
            return self._reject_auth()

        credentials = request_auth.parse_authorization(self.headers.get('Authorization', ''))
        if credentials is None:
            return self._reject_auth()
        agent_id, timestamp, mac = credentials

        if not self._timestamp_in_window(timestamp):
            return self._reject_auth()

        key = self.simulator.cmac_key_for(agent_id)
        if key is None:
            return self._reject_auth()

        canonical = request_auth.build_canonical_request('POST', self.path, agent_id, timestamp, body)
        if not hmac.compare_digest(request_auth.compute_cmac(key, canonical), mac):
            return self._reject_auth()

        self._authenticated_agent_id = agent_id
        return True

    def _reject_auth(self) -> bool:
        """Send the single generic authentication error and return False."""
        self.send_error_response(401, 'Invalid client authentication')
        return False

    @staticmethod
    def _timestamp_in_window(timestamp: str) -> bool:
        """Return True if the timestamp is within the accepted age/skew window."""
        try:
            value = int(timestamp)
        except ValueError:
            return False
        now = int(time.time())
        return now - request_auth.TIMESTAMP_MAX_AGE <= value <= now + request_auth.TIMESTAMP_MAX_SKEW

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

    def _handle_stateless(self, body: bytes) -> None:
        """Handle a ``/stateless`` H/E event batch: structural validation only.

        Success is a ``200`` with an empty body. A malformed batch gets a ``400``. The
        agent-id identity binding (H metadata vs authenticated id) and the ``413`` size
        limit are layered on with the auth middleware and fault modes.
        """
        try:
            metadata, _events = parse_he_batch(body)
        except ValueError:
            self.send_error_response(400, 'Invalid event batch')
            return

        # Identity binding: the batch's agent id must match the authenticated one.
        if self._authenticated_agent_id is not None:
            body_agent_id = metadata.get('wazuh', {}).get('agent', {}).get('id')
            if body_agent_id != self._authenticated_agent_id:
                self.send_error_response(400, 'Invalid event batch')
                return

        self.send_empty(200)

    def _handle_stateful(self, body: bytes) -> None:
        """Handle a ``/stateful`` streamed session: dedup by ``X-Session-Id``, return the result.

        The session blob is accepted (and captured in the request queue) but not parsed;
        it is keyed by the ``X-Session-Id`` header. A missing header is a ``400``.
        """
        session_id = self.headers.get('X-Session-Id')
        if not session_id:
            self.send_error_response(400, 'Bad request')
            return

        self.send_json(200, self.simulator.process_session(session_id))

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

    def _handle_download(self, body: bytes) -> None:
        """Handle a ``/download`` request: stream the requested resource bytes chunked.

        An unknown ``resource_type`` or an unset resource (e.g. no WPK injected) gets a ``404``.
        """
        try:
            request = json.loads(body or b'{}')
        except json.JSONDecodeError:
            self.send_error_response(400, 'Bad request')
            return

        data = self.simulator.download_resource(request.get('resource_type'))
        if data is None:
            self.send_error_response(404, 'Not found')
            return

        self.send_chunked(data)


class RemotedSimulator(BaseSimulator):
    """Simulate the manager side of the Wazuh HTTPS agent protocol.

    The agent connects as an HTTPS client and authenticates every request with an
    AES-CMAC ``Authorization`` header. This simulator stands in for ``wazuh-remoted``:
    it terminates TLS with a self-signed certificate generated at :meth:`start` and
    routes the protocol endpoints (``/control``, ``/stateless``, ``/stateful``,
    ``/download``, ``/config``, ``/stats``).

    The reusable HTTP/TLS transport lives in :mod:`wazuh_testing.tools.https_server`;
    this class holds only the Wazuh protocol behavior and the injectable server state.

    Injectable state (``limits``, ``cluster``, ``groups``, ``config_hash``) is exposed as
    plain attributes with sensible defaults rather than constructor parameters; tests that
    need to customize it assign to these attributes before :meth:`start`. ``settings_hash``
    is derived from the startup response body (read-only), mirroring how the agent computes
    it, so a settings change is forced by mutating limits/cluster/groups. Response shapes
    follow the current contract: startup carries no hash; config_hash appears in notify and
    drives a /download; config is not pushed inline.

    Attributes:
        MODES (list): Valid fault-injection modes for the simulator.
        limits (dict): Module limits returned by the startup response.
        cluster (dict): Cluster ``{name, node}`` returned by the startup response.
        groups (list): Agent groups returned by startup/notify responses.
        merged_mg (bytes): Group config bytes served by /download and hashed into config_hash.
        wpk (bytes): WPK package bytes served by /download for upgrade tasks (None until set).
        stateful_items_processed (int): itemsProcessed reported by the /stateful response.
        stateful_sessions (dict): X-Session-Id -> result cache backing idempotent retries.
        config_hash (str): SHA256 the notify response advertises for the group config.
        settings_hash (str): Derived, read-only SHA256 of the startup response body.
    """

    MODES = ['ACCEPT', 'REJECT_AUTH', 'BAD_REQUEST', 'SERVICE_UNAVAILABLE', 'PAYLOAD_TOO_LARGE']

    def __init__(self,
                 server_ip: str = '127.0.0.1',
                 port: int = DEFAULT_HTTPS_REMOTE_CONNECTION_PORT,
                 mode: str = 'ACCEPT',
                 keys_path: str = WAZUH_CLIENT_KEYS_PATH,
                 verify_auth: bool = False) -> None:
        """Initialize a RemotedSimulator.

        Args:
            server_ip (str, optional): Address to bind the TLS server to. Defaults: '127.0.0.1'.
            port (int, optional): Port to bind the TLS server to. Defaults: 1517 (the HTTPS
                control port, DEFAULT_HTTPS_REMOTE_CONNECTION_PORT) -- not 1514, the legacy
                protocol's port.
            mode (str, optional): Fault-injection mode. Must be one of MODES. Defaults: 'ACCEPT'.
            keys_path (str, optional): Path to the client.keys file. Defaults: WAZUH_CLIENT_KEYS_PATH.
            verify_auth (bool, optional): Enforce AES-CMAC Authorization on every request
                (agent keys resolved from keys_path). Defaults: False.
        """
        super().__init__(server_ip, port, False)

        self.mode = mode
        self.keys_path = keys_path
        self.verify_auth = verify_auth

        # Injectable server state (assign directly before start() to customize).
        self.limits = json.loads(json.dumps(DEFAULT_LIMITS))
        self.cluster = dict(DEFAULT_CLUSTER)
        self.groups = list(DEFAULT_GROUPS)
        self.merged_mg = DEFAULT_MERGED_MG
        self.wpk: Optional[bytes] = None
        self.config_hash = hashlib.sha256(self.merged_mg).hexdigest()

        self._tasks: List[Dict] = []
        self._tasks_lock = threading.Lock()

        # The /stateful response reports itemsProcessed (test-controlled, since the
        # FlatBuffer body is not parsed). stateful_sessions caches each X-Session-Id's
        # result so a whole-session retry with the same id is idempotent (the manager's
        # session-result LRU); TTL eviction is omitted as unnecessary for tests.
        self.stateful_items_processed = 0
        self.stateful_sessions: Dict[str, Dict] = {}
        self._sessions_lock = threading.Lock()

        # Last documents pushed by the agent (populated by /config and /stats).
        self.last_config: Optional[Dict] = None
        self.last_stats: Optional[Dict] = None

        self._requests: List[Dict] = []
        self._requests_lock = threading.Lock()
        self._httpd: Optional[TLSHTTPServer] = None
        self._thread: Optional[threading.Thread] = None
        self._cert_dir: Optional[str] = None

    # Properties.

    @property
    def requests(self) -> List[Dict]:
        """Snapshot of all received requests (each a dict: method/path/headers/agent_id/body)."""
        return self.get_requests()

    @property
    def settings_hash(self) -> str:
        """SHA-256 of the exact startup response body.

        Matches how the agent derives its settings baseline (over the received startup
        bytes), so a notify never triggers a spurious settings refresh. Read-only and
        derived: to force a settings change, mutate limits/cluster/groups.
        """
        return hashlib.sha256(json.dumps(self.startup_response()).encode()).hexdigest()

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
        """Remove all recorded requests."""
        with self._requests_lock:
            self._requests.clear()

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
        with self._requests_lock:
            self._requests.append({
                'method': method,
                'path': path,
                'headers': dict(headers.items()),
                'agent_id': self._agent_id_from_headers(headers),
                'body': body,
            })

    def get_requests(self, path: str = None) -> List[Dict]:
        """Return a snapshot of captured requests, optionally filtered by endpoint path.

        Args:
            path (str, optional): If given, only requests whose target path (ignoring any
                query string) equals this value are returned.

        Returns:
            List[Dict]: Copied request records, in arrival order.
        """
        with self._requests_lock:
            snapshot = list(self._requests)
        if path is None:
            return snapshot
        return [request for request in snapshot if urlsplit(request['path']).path == path]

    def last_request(self, path: str = None) -> Optional[Dict]:
        """Return the most recent captured request (optionally for a path), or None."""
        matches = self.get_requests(path)
        return matches[-1] if matches else None

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

    def cmac_key_for(self, agent_id: str) -> Optional[bytes]:
        """Resolve an agent's 16-byte AES-CMAC key from client.keys.

        Args:
            agent_id (str): The agent identifier to look up.

        Returns:
            Optional[bytes]: The 16-byte key, or None if the agent is unknown or its key
                is not valid CMAC key material.
        """
        for entry in get_client_keys(self.keys_path):
            if entry['id'] == agent_id:
                try:
                    return request_auth.derive_cmac_key(entry['key'])
                except ValueError:
                    return None
        return None

    def process_session(self, session_id: str) -> Dict:
        """Return the ``/stateful`` result for a session id; retries are idempotent.

        The first request for a given id records and returns a result; a retry with the
        same id returns the cached result unchanged (whole-session retry dedup).

        Args:
            session_id (str): The ``X-Session-Id`` identifying the session.

        Returns:
            Dict: The session result ``{status, sessionId, itemsProcessed}``.
        """
        with self._sessions_lock:
            if session_id not in self.stateful_sessions:
                self.stateful_sessions[session_id] = {
                    'status': 'ok',
                    'sessionId': session_id,
                    'itemsProcessed': self.stateful_items_processed,
                }
            return self.stateful_sessions[session_id]

    def download_resource(self, resource_type: str) -> Optional[bytes]:
        """Return the bytes ``/download`` serves for a resource type, or None if unavailable.

        ``config`` serves the merged.mg; ``wpk`` serves the injected WPK bytes (None until set).

        Args:
            resource_type (str): The requested resource type (``config`` or ``wpk``).

        Returns:
            Optional[bytes]: The resource bytes, or None if the type is unknown or unset.
        """
        if resource_type == 'config':
            return self.merged_mg
        if resource_type == 'wpk':
            return self.wpk
        return None

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
