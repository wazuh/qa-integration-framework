"""
Copyright (C) 2015-2026, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

A reference client for the enrollment-token bootstrap.

Walks the sequence an agent holding an enrollment token performs, in order, from a token and
nothing else::

    decode the token
    GET  /cacerts        UNVERIFIED -- there is no anchor yet, by definition
    SHA-256 the fetched certificate's SubjectPublicKeyInfo and compare it to the token's pin
    reconnect            FULLY VERIFIED, trusting the fetched certificate and nothing else
    POST /enroll         to obtain an identity
    POST /control        startup, signed with the key enrollment returned

WHAT THIS IS FOR. The agent side of this flow exists only as disconnected pieces:
hc_fetch_cacerts() has no production caller, the installer parses a token and logs two of its
fields before discarding the rest, and the pin primitive is a standalone function. Wiring them
together is a separate issue. Until then this is the only way to exercise the manager side of the
flow end to end, and it doubles as an executable specification of what that wiring has to do --
including the parts that are easy to get subtly wrong and expensive to find late: which target is
prefixed, that the digest is over the SubjectPublicKeyInfo rather than the certificate, that a
matching pin is not the same thing as a verified connection, and that the two legs run on two
different connections with two different postures.

WHAT IT DOES NOT ESTABLISH. Not one line of the agent runs here, so this cannot catch a bug in
spkiSha256FromPem, in hc_fetch_cacerts' truncation at HC_MAX_CACERTS_BODY, in the installer's
shell decoder, or in the agent's configuration-reload ordering. Python's OpenSSL and libcurl also
differ on cipher policy, session resumption and SNI, so a TLS floor asserted here is not the floor
curl negotiates. It shows that a correct client CAN complete the flow against this manager mock,
not that the agent does.

Deliberately five legs and no more: no retry, no backoff, no notify loop, no /stateless. The
moment this grows behaviour of its own it stops being a specification and starts needing its own
specification.
"""
import hmac
import http.client
import json
import ssl
import time
from typing import Dict, NamedTuple, Optional, Tuple

from wazuh_testing.utils import jwt_enroll, request_auth
from wazuh_testing.utils.enrollment_token import (EnrollmentTokenError, adr_to_target,
                                                  b64url_decode, decode_token)

# Every way the walk can stop short. Each is a distinct diagnosis an agent would have to log
# differently, which is the reason they are separate values rather than one failure:
# 'pin_mismatch' means the manager is not the one the token names -- possibly an attack --
# while 'pin_malformed' means the token itself is not usable, and 'verified_connect_failed'
# means the pinned certificate is genuine but cannot vouch for the listener serving it.
BOOTSTRAP_REASONS = (
    'token_invalid',
    'unreachable',
    'cacerts_http_error',
    'cacerts_not_pem',
    'pin_malformed',
    'pin_mismatch',
    'verified_connect_failed',
    'enroll_failed',
    'startup_failed',
)

PEM_CERTIFICATE_HEADER = b'-----BEGIN CERTIFICATE-----'
SPKI_PIN_BYTES = 32
SPKI_PIN_B64_CHARS = 43


class BootstrapError(Exception):
    """The walk stopped. ``reason`` is one of :data:`BOOTSTRAP_REASONS`."""

    def __init__(self, reason: str, detail: str = '') -> None:
        self.reason = reason
        super().__init__(f'{reason}: {detail}' if detail else reason)


class BootstrapResult(NamedTuple):
    """What a completed walk learned."""

    ca_pem: bytes
    ca_pin: str
    cacerts_status: int
    cacerts_content_type: Optional[str]
    enroll: Dict
    startup: Dict


class EnrollmentBootstrapClient:
    """Performs the enrollment-token bootstrap against a manager named only by the token.

    Each leg is callable on its own, so a test can stop after any one of them and assert on what
    the manager did and did not receive -- which is how the negative cases are expressed: a pin
    mismatch has to be observable as "it fetched once and never came back", not merely as an
    exception here.
    """

    def __init__(self, token: str, agent_name: str, agent_version: str = '5.0.0',
                 timeout: float = 10.0,
                 tls_minimum_version: ssl.TLSVersion = ssl.TLSVersion.TLSv1_3,
                 enroll_password: Optional[str] = None,
                 client_certificate: Optional[Tuple[str, str]] = None) -> None:
        """Prepare a walk.

        Args:
            token (str): The enrollment token. The ONLY source of host, port and prefix -- that
                is what makes this a specification of the token's meaning rather than a script.
            agent_name (str): Name to enroll under.
            agent_version (str, optional): Version to report. Defaults: '5.0.0'.
            timeout (float, optional): Per-request timeout in seconds. Defaults: 10.0.
            tls_minimum_version (ssl.TLSVersion, optional): Floor for both legs, mirroring the
                agent's unconditional CURLOPT_SSLVERSION of TLS 1.3 -- which it sets even on the
                unverified fetch. Defaults: TLSv1_3.
            enroll_password (str, optional): Enables /enroll's password gate.
            client_certificate (Tuple[str, str], optional): (certfile, keyfile) for an mTLS
                listener. Note that such a listener cannot serve this flow at all, on a real
                manager as much as on the mock: /cacerts sits behind the same
                verify_fail_if_no_peer_cert as everything else.

        Raises:
            BootstrapError: token_invalid, if the token does not decode.
        """
        try:
            self.token = decode_token(token)
        except EnrollmentTokenError as error:
            raise BootstrapError('token_invalid', str(error)) from error

        self.host, self.port, self.prefix = adr_to_target(self.token.adr)
        self.agent_name = agent_name
        self.agent_version = agent_version
        self.timeout = timeout
        self.tls_minimum_version = tls_minimum_version
        self.enroll_password = enroll_password
        self.client_certificate = client_certificate

    # Targets.

    def target(self, endpoint: str) -> str:
        """The wire target for an endpoint, under the prefix the token carries.

        Every endpoint, /cacerts included: the agent folds the prefix into all of them via
        prefixedTarget(), matching the manager, which registers them all under global_prefix.
        """
        return f'/{self.prefix}{endpoint}' if self.prefix else endpoint

    # TLS postures.

    @property
    def unverified_context(self) -> ssl.SSLContext:
        """The posture of the /cacerts fetch: verifies nothing, but still floors the protocol.

        Exposed rather than built inline so a test can assert on it. "Unverified but TLS-1.3
        floored" is the combination that matters and the one a higher-level HTTP library cannot
        express without reaching for a custom adapter.
        """
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        context.minimum_version = self.tls_minimum_version
        self._apply_client_certificate(context)
        return context

    def verified_context(self, ca_pem: bytes) -> ssl.SSLContext:
        """The posture of the reconnect: `ca_pem` is the ONLY thing that can vouch for the peer.

        Loaded with ``cadata`` so the bytes fetched over the wire are used exactly as they
        arrived, and ``load_default_certs()`` is never called -- a system anchor sneaking in
        would make the whole exercise meaningless, since the connection could then succeed
        without the pinned certificate having anything to do with it.
        """
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = self.tls_minimum_version
        context.verify_mode = ssl.CERT_REQUIRED
        context.check_hostname = True
        context.load_verify_locations(cadata=ca_pem.decode())
        self._apply_client_certificate(context)
        return context

    def _apply_client_certificate(self, context: ssl.SSLContext) -> None:
        if self.client_certificate is not None:
            context.load_cert_chain(certfile=self.client_certificate[0],
                                    keyfile=self.client_certificate[1])

    # Legs.

    def fetch_cacerts(self) -> Tuple[int, Optional[str], bytes]:
        """Leg 1: GET /cacerts, unverified.

        Returns:
            Tuple[int, Optional[str], bytes]: (status, content type, body).

        Raises:
            BootstrapError: unreachable.
        """
        connection = self._connect(self.unverified_context)
        try:
            connection.request('GET', self.target('/cacerts'))
            response = connection.getresponse()
            return response.status, response.getheader('Content-Type'), response.read()
        except (OSError, http.client.HTTPException) as error:
            raise BootstrapError('unreachable', f'{type(error).__name__}: {error}') from error
        finally:
            connection.close()

    def check_pin(self, ca_pem: bytes) -> str:
        """Leg 2: compare the fetched certificate's SPKI pin against the token's.

        Splits malformed from mismatched exactly as the agent's spkiPinCompare does, because they
        are different diagnoses: a malformed pin is a bad token, a mismatch is a manager that is
        not the one the token names.

        Returns:
            str: The computed pin, when it matches.

        Raises:
            BootstrapError: cacerts_not_pem, pin_malformed or pin_mismatch.
        """
        # Imported here rather than at module scope: importing the simulator pulls in the whole
        # mock manager, and this client has no business depending on it.
        from wazuh_testing.tools.simulators.remoted_simulator import spki_pin

        if PEM_CERTIFICATE_HEADER not in ca_pem:
            raise BootstrapError('cacerts_not_pem',
                                 f'no certificate block in {len(ca_pem)} bytes')
        try:
            computed = spki_pin(ca_pem)
        except Exception as error:
            raise BootstrapError('cacerts_not_pem', str(error)) from error

        expected = self.token.pin
        if expected is None:
            # An --embed-ca token carries the certificate itself, so there is nothing to fetch
            # and nothing to compare; a caller reaching here has sequenced the walk wrongly.
            raise BootstrapError('pin_malformed', 'token carries a ca anchor, not a pin')
        if len(expected) != SPKI_PIN_B64_CHARS:
            raise BootstrapError('pin_malformed', f'{len(expected)} characters')
        try:
            expected_bytes = b64url_decode(expected)
        except EnrollmentTokenError as error:
            raise BootstrapError('pin_malformed', str(error)) from error
        if len(expected_bytes) != SPKI_PIN_BYTES:
            raise BootstrapError('pin_malformed', f'{len(expected_bytes)} bytes')

        # Neither value is secret -- both are public -- so this is hygiene rather than a
        # side-channel mitigation, matching what the agent's own header says about it.
        if not hmac.compare_digest(b64url_decode(computed), expected_bytes):
            raise BootstrapError('pin_mismatch', f'served {computed}, token says {expected}')

        return computed

    def open_verified(self, ca_pem: bytes) -> http.client.HTTPSConnection:
        """Leg 3: reconnect, verifying against `ca_pem` alone.

        Raises:
            BootstrapError: verified_connect_failed -- which is where a genuine certificate that
                cannot vouch for this listener lands, as does a listener whose name the
                certificate does not cover.
        """
        connection = self._connect(self.verified_context(ca_pem))
        try:
            connection.connect()
        except ssl.SSLError as error:
            raise BootstrapError('verified_connect_failed',
                                 f'{type(error).__name__}: {error}') from error
        except OSError as error:
            raise BootstrapError('unreachable', f'{type(error).__name__}: {error}') from error
        return connection

    def enroll(self, connection: http.client.HTTPSConnection) -> Dict:
        """Leg 4: POST /enroll over an already-verified connection.

        Raises:
            BootstrapError: enroll_failed.
        """
        body = json.dumps({'name': self.agent_name, 'version': self.agent_version}).encode()
        target = self.target('/enroll')
        headers = {'Content-Type': 'application/json',
                   'protocol-version': request_auth.PROTOCOL_VERSION}

        # A `wazuh-enroll+jwt` bearer, not the AES-CMAC header this used to send: wazuh/wazuh
        # #38582 retired that scheme. The token's own credential outranks a configured password,
        # the same precedence the agent applies (enrollClient.cpp) -- an enrollment that carries
        # a credential of its own must not also sign with a possibly unrelated authd.pass. The
        # bearer binds time and a fresh jti, not the target or the body.
        if self.token.key_id is not None:
            headers['Authorization'] = 'Bearer ' + jwt_enroll.sign(
                jwt_enroll.derive_token_key(self.token.key_secret),
                kid=jwt_enroll.b64url_encode(self.token.key_id))
        elif self.enroll_password is not None:
            headers['Authorization'] = 'Bearer ' + jwt_enroll.sign(
                jwt_enroll.derive_password_key(self.enroll_password))

        payload = self._send(connection, 'POST', target, body, headers, 'enroll_failed')
        for field in ('id', 'key'):
            if field not in payload:
                raise BootstrapError('enroll_failed', f'response has no {field!r}')
        return payload

    def control_startup(self, connection: http.client.HTTPSConnection, agent_id: str,
                        key: str) -> Dict:
        """Leg 5: POST /control startup, signed with the identity enrollment just returned.

        Signing with a key that only exists in the manager's memory is the point: it proves the
        enrollment was real and immediately usable, with no client.keys file involved anywhere.

        Raises:
            BootstrapError: startup_failed.
        """
        body = json.dumps({'type': 'startup'}).encode()
        target = self.target('/control')
        timestamp = int(time.time())
        headers = {
            'Content-Type': 'application/json',
            'protocol-version': request_auth.PROTOCOL_VERSION,
            'Authorization': request_auth.sign_authorization(
                'POST', target, agent_id, timestamp, body, request_auth.derive_cmac_key(key)),
        }

        return self._send(connection, 'POST', target, body, headers, 'startup_failed')

    def run(self) -> BootstrapResult:
        """Walk every leg in order and return what was learned.

        Raises:
            BootstrapError: at the first leg that fails, with the reason naming which.
        """
        status, content_type, ca_pem = self.fetch_cacerts()
        if status != 200:
            raise BootstrapError('cacerts_http_error', f'HTTP {status}: {ca_pem[:120]!r}')

        pin = self.check_pin(ca_pem)

        connection = self.open_verified(ca_pem)
        try:
            enrollment = self.enroll(connection)
            startup = self.control_startup(connection, enrollment['id'], enrollment['key'])
        finally:
            connection.close()

        return BootstrapResult(ca_pem=ca_pem, ca_pin=pin, cacerts_status=status,
                               cacerts_content_type=content_type, enroll=enrollment,
                               startup=startup)

    # Internals.

    def _connect(self, context: ssl.SSLContext) -> http.client.HTTPSConnection:
        return http.client.HTTPSConnection(self.host, self.port, context=context,
                                           timeout=self.timeout)

    def _send(self, connection: http.client.HTTPSConnection, method: str, target: str,
              body: bytes, headers: Dict, reason: str) -> Dict:
        """Send one request on an open connection and return its JSON body."""
        try:
            connection.request(method, target, body=body, headers=headers)
            response = connection.getresponse()
            raw = response.read()
        except (OSError, http.client.HTTPException) as error:
            raise BootstrapError(reason, f'{type(error).__name__}: {error}') from error

        if response.status != 200:
            raise BootstrapError(reason, f'HTTP {response.status}: {raw[:200]!r}')
        try:
            return json.loads(raw)
        except json.JSONDecodeError as error:
            raise BootstrapError(reason, f'body is not JSON: {raw[:120]!r}') from error
