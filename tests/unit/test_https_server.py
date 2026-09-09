"""
Copyright (C) 2015-2026, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

Unit tests for the reusable TLS transport building blocks in wazuh_testing.tools.https_server.

Two things are under test here, both prerequisites for the enrollment-token bootstrap that
RemotedSimulator hosts (fetch a CA over an unverified GET /cacerts, pin it, then reconnect fully
verified against that CA alone):

1. The certificate helpers. A client performing the verified reconnect checks the chain *and* the
   hostname, so the listener needs a leaf that a fetched CA actually signs and whose
   SubjectAlternativeName covers the address being connected to. The historical
   generate_self_signed_certificate() produces neither -- it emits a CN=Manager CA with no SAN,
   which is why every agentd integration suite disables verification.

2. TLSHTTPServer's handshake accounting. A client that refuses the certificate this listener
   serves is the observable half of a pin-mismatch or wrong-name test, and until the listener
   stopped wrapping its own accept socket that event was discarded by socketserver before any
   error hook ran (see TLSHTTPServer.get_request).

Run with:  PYTHONPATH=src python3 -m pytest tests/unit/test_https_server.py -v
"""
import http.client
import socket
import ssl
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler

import pytest
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import ec

from wazuh_testing.tools.https_server import (BaseTLSRequestHandler, TLSHTTPServer,
                                              generate_ca_certificate, generate_leaf_certificate,
                                              write_pem_pair)


def free_port() -> int:
    """Return a port nothing is listening on."""
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        return probe.getsockname()[1]


def ca_signs(ca_pem: bytes, leaf_pem: bytes) -> bool:
    """Whether the CA's key actually signed the leaf. Signature only: no dates, no chain."""
    ca = x509.load_pem_x509_certificate(ca_pem)
    leaf = x509.load_pem_x509_certificate(leaf_pem)
    try:
        ca.public_key().verify(leaf.signature, leaf.tbs_certificate_bytes,
                               ec.ECDSA(leaf.signature_hash_algorithm))
    except Exception:
        return False
    return True


class _EchoHandler(BaseTLSRequestHandler):
    """Answers any GET with a fixed body, so a test can prove a connection completed."""

    def do_GET(self) -> None:
        self.send_body(b'ok', 200, 'text/plain')


def serve(certificate_pem: bytes, key_pem: bytes, **kwargs):
    """Start a TLSHTTPServer on a free port serving the given material. Returns (server, port)."""
    certfile, keyfile = write_pem_pair(tempfile.mkdtemp(prefix='https_server_test_'),
                                       certificate_pem, key_pem)
    port = free_port()
    server = TLSHTTPServer(('127.0.0.1', port), _EchoHandler,
                           certfile=certfile, keyfile=keyfile, **kwargs)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, port


def anchored_context(ca_pem: bytes) -> ssl.SSLContext:
    """A client context trusting exactly one CA, with full verification -- no system anchors."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cadata=ca_pem.decode())
    return context


# ---------------------------------------------------------------------------------------------
# Certificate helpers
# ---------------------------------------------------------------------------------------------

def test_the_ca_is_a_self_signed_signing_ca():
    ca_pem, _ = generate_ca_certificate()
    ca = x509.load_pem_x509_certificate(ca_pem)

    assert ca.subject == ca.issuer
    basic = ca.extensions.get_extension_for_class(x509.BasicConstraints).value
    assert basic.ca is True
    # path_length=0: it signs leaves only, never another CA.
    assert basic.path_length == 0
    key_usage = ca.extensions.get_extension_for_class(x509.KeyUsage).value
    assert key_usage.key_cert_sign is True
    assert key_usage.digital_signature is False
    # No ExtendedKeyUsage: it would constrain what this CA may issue in some verifiers.
    with pytest.raises(x509.ExtensionNotFound):
        ca.extensions.get_extension_for_class(x509.ExtendedKeyUsage)


def test_the_leaf_is_a_server_certificate_signed_by_the_ca():
    ca_pem, ca_key = generate_ca_certificate()
    leaf_pem, _ = generate_leaf_certificate(ca_pem, ca_key)
    ca = x509.load_pem_x509_certificate(ca_pem)
    leaf = x509.load_pem_x509_certificate(leaf_pem)

    assert leaf.issuer == ca.subject
    assert leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False
    assert leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value == \
        x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH])
    # The chain is linkable by identifier as well as by signature.
    assert leaf.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value.key_identifier \
        == ca.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
    assert ca_signs(ca_pem, leaf_pem)


def test_the_leaf_carries_loopback_in_its_subject_alternative_name():
    """Verifying a connection to an IP literal has no CommonName fallback, so the SAN is the
    only thing that can satisfy it -- and the CN is deliberately left as something else."""
    ca_pem, ca_key = generate_ca_certificate()
    leaf_pem, _ = generate_leaf_certificate(ca_pem, ca_key)
    leaf = x509.load_pem_x509_certificate(leaf_pem)

    san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.DNSName) == ['localhost']
    assert [str(address) for address in san.get_values_for_type(x509.IPAddress)] == \
        ['127.0.0.1', '::1']
    assert leaf.subject.rfc4514_string() == 'CN=Manager'


def test_san_entries_are_configurable_and_omitted_entirely_when_empty():
    ca_pem, ca_key = generate_ca_certificate()

    named, _ = generate_leaf_certificate(ca_pem, ca_key, hostnames=('other.invalid',),
                                         ip_addresses=())
    san = x509.load_pem_x509_certificate(named).extensions.get_extension_for_class(
        x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.DNSName) == ['other.invalid']
    assert san.get_values_for_type(x509.IPAddress) == []

    # No SAN at all is the historical shape, and must stay expressible.
    bare, _ = generate_leaf_certificate(ca_pem, ca_key, hostnames=(), ip_addresses=())
    with pytest.raises(x509.ExtensionNotFound):
        x509.load_pem_x509_certificate(bare).extensions.get_extension_for_class(
            x509.SubjectAlternativeName)


def test_certificates_are_backdated_so_a_lagging_clock_does_not_break_verification():
    ca_pem, _ = generate_ca_certificate()
    ca = x509.load_pem_x509_certificate(ca_pem)
    # Naive UTC, which is what the non-_utc accessors return on cryptography 41.
    assert ca.not_valid_before < ca.not_valid_after
    assert (ca.not_valid_after - ca.not_valid_before).days > 3650


def test_each_pem_holds_exactly_one_certificate():
    """load_cert_chain() serves every certificate in the file. If the CA were ever appended to the
    listener's PEM, a client could lift the /cacerts bytes off the handshake -- which would void
    the provenance property the separate certificates exist to give, with every test still green."""
    ca_pem, ca_key = generate_ca_certificate()
    leaf_pem, _ = generate_leaf_certificate(ca_pem, ca_key)

    assert leaf_pem.count(b'-----BEGIN CERTIFICATE-----') == 1
    assert ca_pem.count(b'-----BEGIN CERTIFICATE-----') == 1
    assert ca_pem not in leaf_pem


def test_rsa_material_is_available_for_callers_that_need_it():
    ca_pem, ca_key = generate_ca_certificate(key_type='rsa', key_size=2048)
    leaf_pem, _ = generate_leaf_certificate(ca_pem, ca_key, key_type='rsa', key_size=2048)

    assert x509.load_pem_x509_certificate(ca_pem).public_key().key_size == 2048
    assert x509.load_pem_x509_certificate(leaf_pem).public_key().key_size == 2048


def test_an_unknown_key_type_is_rejected():
    with pytest.raises(ValueError, match="key_type"):
        generate_ca_certificate(key_type='dsa')


# ---------------------------------------------------------------------------------------------
# The property the whole bootstrap depends on
# ---------------------------------------------------------------------------------------------

def test_a_client_trusting_only_the_ca_completes_a_fully_verified_connection():
    """The verified-reconnect leg: one fetched CA as the sole anchor, peer AND hostname checked,
    against an IP literal. If this cannot pass, no pin can ever be turned into trust."""
    ca_pem, ca_key = generate_ca_certificate()
    leaf_pem, leaf_key = generate_leaf_certificate(ca_pem, ca_key)
    server, port = serve(leaf_pem, leaf_key)

    try:
        context = anchored_context(ca_pem)
        assert context.verify_mode == ssl.CERT_REQUIRED
        assert context.check_hostname is True
        assert len(context.get_ca_certs()) == 1

        connection = http.client.HTTPSConnection('127.0.0.1', port, context=context, timeout=10)
        connection.request('GET', '/')
        response = connection.getresponse()
        assert (response.status, response.read()) == (200, b'ok')
        connection.close()

        assert server.handshake_failures == []
    finally:
        server.shutdown()
        server.server_close()


def test_a_client_trusting_an_unrelated_ca_is_refused_and_the_refusal_is_recorded():
    """The negative half. Before TLSHTTPServer wrapped per connection, socketserver discarded this
    event (ssl.SSLError is an OSError) and the simulator had no evidence it ever happened."""
    ca_pem, ca_key = generate_ca_certificate()
    leaf_pem, leaf_key = generate_leaf_certificate(ca_pem, ca_key)
    unrelated_pem, _ = generate_ca_certificate(common_name='Unrelated CA')
    server, port = serve(leaf_pem, leaf_key)

    try:
        with pytest.raises(ssl.SSLCertVerificationError):
            http.client.HTTPSConnection('127.0.0.1', port, context=anchored_context(unrelated_pem),
                                        timeout=10).request('GET', '/')

        deadline = time.time() + 5
        while not server.handshake_failures and time.time() < deadline:
            time.sleep(0.05)
        assert len(server.handshake_failures) == 1
        assert server.handshake_failures[0]['reason'] == 'TLSV1_ALERT_UNKNOWN_CA'
    finally:
        server.shutdown()
        server.server_close()


def test_a_leaf_without_a_matching_san_fails_the_hostname_check_only():
    """Path validation succeeds and the hostname check fails, which is a different failure from a
    wrong anchor and must stay distinguishable from it."""
    ca_pem, ca_key = generate_ca_certificate()
    leaf_pem, leaf_key = generate_leaf_certificate(ca_pem, ca_key,
                                                   hostnames=('other.invalid',), ip_addresses=())
    server, port = serve(leaf_pem, leaf_key)

    try:
        with pytest.raises(ssl.SSLCertVerificationError) as error:
            http.client.HTTPSConnection('127.0.0.1', port, context=anchored_context(ca_pem),
                                        timeout=10).request('GET', '/')
        # Asserted on the code, not the message text, which OpenSSL is free to reword. The code
        # is the IP-specific one because the connection names an IP literal: there is no
        # CommonName fallback on that path, only the iPAddress SAN entry this leaf lacks.
        assert error.value.verify_code == 64  # X509_V_ERR_IP_ADDRESS_MISMATCH

        # Trust itself was fine: the same certificate is accepted without the hostname check.
        lenient = anchored_context(ca_pem)
        lenient.check_hostname = False
        connection = http.client.HTTPSConnection('127.0.0.1', port, context=lenient, timeout=10)
        connection.request('GET', '/')
        assert connection.getresponse().status == 200
        connection.close()
    finally:
        server.shutdown()
        server.server_close()


def test_a_plain_http_probe_is_recorded_but_distinguishable_from_a_refusal():
    """Expected noise, kept rather than filtered: a silently dropped category is how the refusal
    case went unnoticed in the first place. Tests filter on `reason`."""
    ca_pem, ca_key = generate_ca_certificate()
    leaf_pem, leaf_key = generate_leaf_certificate(ca_pem, ca_key)
    server, port = serve(leaf_pem, leaf_key)

    try:
        probe = socket.create_connection(('127.0.0.1', port), timeout=10)
        probe.sendall(b'GET / HTTP/1.0\r\n\r\n')
        try:
            probe.recv(64)  # The listener drops the connection once the handshake fails.
        except OSError:
            pass
        probe.close()

        deadline = time.time() + 5
        while not server.handshake_failures and time.time() < deadline:
            time.sleep(0.05)
        assert [failure['reason'] for failure in server.handshake_failures] == ['HTTP_REQUEST']
    finally:
        server.shutdown()
        server.server_close()


def test_the_listening_socket_is_plain_tcp_and_the_context_is_retained():
    """Both are load-bearing: the accept socket must not be an SSLSocket (or the handshake runs
    inside get_request's caller, which swallows it), and the context must outlive __init__ so
    each connection can be wrapped."""
    ca_pem, ca_key = generate_ca_certificate()
    leaf_pem, leaf_key = generate_leaf_certificate(ca_pem, ca_key)
    server, _ = serve(leaf_pem, leaf_key)

    try:
        assert not isinstance(server.socket, ssl.SSLSocket)
        assert isinstance(server.ssl_context, ssl.SSLContext)
    finally:
        server.shutdown()
        server.server_close()


def test_an_opt_in_minimum_tls_version_is_enforced():
    """Off by default -- a hard floor would fail existing suites on an unknown CI OpenSSL build
    for a reason unrelated to what they test."""
    ca_pem, ca_key = generate_ca_certificate()
    leaf_pem, leaf_key = generate_leaf_certificate(ca_pem, ca_key)
    server, port = serve(leaf_pem, leaf_key, min_tls_version=ssl.TLSVersion.TLSv1_3)

    try:
        assert server.ssl_context.minimum_version == ssl.TLSVersion.TLSv1_3

        capped = anchored_context(ca_pem)
        capped.maximum_version = ssl.TLSVersion.TLSv1_2
        with pytest.raises(ssl.SSLError):
            http.client.HTTPSConnection('127.0.0.1', port, context=capped,
                                        timeout=10).request('GET', '/')

        connection = http.client.HTTPSConnection('127.0.0.1', port, context=anchored_context(ca_pem),
                                                 timeout=10)
        connection.request('GET', '/')
        assert connection.getresponse().status == 200
        assert connection.sock.version() == 'TLSv1.3'
        connection.close()
    finally:
        server.shutdown()
        server.server_close()


# ---------------------------------------------------------------------------------------------
# send_body
# ---------------------------------------------------------------------------------------------

def test_send_body_sends_exact_bytes_with_content_length_and_no_chunking():
    """A /cacerts body must arrive byte for byte: the agent copies it into a fixed char[8192],
    and a test asserting on those bytes should not have to de-chunk first."""
    ca_pem, ca_key = generate_ca_certificate()
    leaf_pem, leaf_key = generate_leaf_certificate(ca_pem, ca_key)
    server, port = serve(leaf_pem, leaf_key)

    try:
        connection = http.client.HTTPSConnection('127.0.0.1', port, context=anchored_context(ca_pem),
                                                 timeout=10)
        connection.request('GET', '/')
        response = connection.getresponse()
        body = response.read()
        assert body == b'ok'
        assert response.getheader('Content-Type') == 'text/plain'
        assert response.getheader('Content-Length') == str(len(body))
        assert response.getheader('Transfer-Encoding') is None
        connection.close()
    finally:
        server.shutdown()
        server.server_close()
