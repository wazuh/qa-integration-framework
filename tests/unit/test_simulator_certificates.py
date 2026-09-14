"""
Copyright (C) 2015-2026, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

Unit tests for RemotedSimulator's two certificate topologies.

The enrollment-token bootstrap ends with the agent reconnecting fully verified against the CA it
fetched from GET /cacerts, trusting nothing else. Whether that can succeed at all is decided here,
before any route exists:

- Default (``use_bootstrap_chain=False``): the listener's certificate and the /cacerts one are two
  unrelated self-signed certificates. A client can pin the fetched body and still fail to verify
  this listener against it. That is the historical shape, and it is the fixture that proves a
  matching pin is not by itself trust.
- ``use_bootstrap_chain=True``: /cacerts hands out a real CA that signed the leaf the listener
  presents, with a SubjectAlternativeName covering the address under test. This is the manager's
  own shape (remote.https.ca_certificate signs the served certificate).

In both, the /cacerts certificate is never equal to the listener's and is never appended to the
served chain -- otherwise a test asserting on the /cacerts body would prove nothing, since the
client could have lifted those bytes off the handshake.

Run with:  PYTHONPATH=src python3 -m pytest tests/unit/test_simulator_certificates.py -v
"""
import http.client
import socket
import ssl
import time

import pytest
from cryptography import x509

from wazuh_testing.tools.simulators.remoted_simulator import RemotedSimulator, spki_pin


def free_port() -> int:
    """Return a port nothing is listening on."""
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 0))
        return probe.getsockname()[1]


def anchored_context(ca_pem: bytes) -> ssl.SSLContext:
    """A client context trusting exactly one CA, with full verification -- no system anchors."""
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cadata=ca_pem.decode())
    return context


def test_the_default_topology_is_unchanged_and_the_two_certificates_are_unrelated():
    """The guard on the default: every existing RemotedSimulator() must keep behaving as it did."""
    simulator = RemotedSimulator(port=free_port())

    assert simulator.use_bootstrap_chain is False
    assert simulator.cacerts_pem != simulator.tls_certificate_pem
    assert simulator.cacerts_pin != simulator.tls_pin
    # Unrelated, not merely different: the /cacerts certificate did not sign what is served.
    assert simulator.cacerts_signs_listener is False


def test_the_bootstrap_chain_makes_the_cacerts_certificate_sign_the_listener():
    simulator = RemotedSimulator(port=free_port(), use_bootstrap_chain=True)

    assert simulator.cacerts_signs_listener is True
    authority = x509.load_pem_x509_certificate(simulator.cacerts_pem)
    leaf = x509.load_pem_x509_certificate(simulator.tls_certificate_pem)
    assert authority.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is True
    assert leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False
    assert leaf.issuer == authority.subject
    # Still two distinct certificates, so a /cacerts body assertion still means something.
    assert simulator.cacerts_pem != simulator.tls_certificate_pem
    assert simulator.cacerts_pin != simulator.tls_pin


def test_the_listener_serves_the_leaf_alone_and_never_the_ca():
    """load_cert_chain() serves every certificate in the file. If the CA were ever appended, the
    /cacerts bytes would be derivable from the handshake and the provenance property would be
    silently void -- with every other assertion still green."""
    for use_chain in (False, True):
        simulator = RemotedSimulator(port=free_port(), use_bootstrap_chain=use_chain)
        assert simulator.tls_certificate_pem.count(b'-----BEGIN CERTIFICATE-----') == 1
        assert simulator.cacerts_pem not in simulator.tls_certificate_pem


def test_the_generated_leaf_covers_the_bound_address_in_its_san():
    """Verifying a connection named by an IP literal has no CommonName fallback, so the iPAddress
    SAN entry is the only thing that can satisfy it."""
    simulator = RemotedSimulator(port=free_port(), use_bootstrap_chain=True)

    leaf = x509.load_pem_x509_certificate(simulator.tls_certificate_pem)
    san = leaf.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert '127.0.0.1' in [str(address) for address in san.get_values_for_type(x509.IPAddress)]
    assert 'localhost' in san.get_values_for_type(x509.DNSName)
    # And the CN is deliberately not the address, so only the SAN can satisfy the check.
    assert leaf.subject.rfc4514_string() == 'CN=Manager'


def test_server_ip_is_folded_into_the_san_without_the_caller_restating_it():
    ipv6 = RemotedSimulator(port=free_port(), server_ip='::1', use_bootstrap_chain=True)
    san = x509.load_pem_x509_certificate(ipv6.tls_certificate_pem).extensions.get_extension_for_class(
        x509.SubjectAlternativeName).value
    assert '::1' in [str(address) for address in san.get_values_for_type(x509.IPAddress)]

    # A non-literal server_ip is a DNS name, not an IP entry.
    named = RemotedSimulator(port=free_port(), server_ip='manager.example.com',
                             use_bootstrap_chain=True)
    san = x509.load_pem_x509_certificate(named.tls_certificate_pem).extensions.get_extension_for_class(
        x509.SubjectAlternativeName).value
    assert 'manager.example.com' in san.get_values_for_type(x509.DNSName)


def test_the_cacerts_private_key_is_retained_so_a_test_can_sign_with_the_anchor():
    """It used to be discarded, which is why the anchor could never issue anything -- and so why
    a wrong-name leaf that nonetheless chains to the pinned CA was not expressible."""
    from wazuh_testing.tools.https_server import generate_leaf_certificate

    simulator = RemotedSimulator(port=free_port(), use_bootstrap_chain=True)
    assert simulator.cacerts_key_pem is not None

    other, _ = generate_leaf_certificate(simulator.cacerts_pem, simulator.cacerts_key_pem,
                                         hostnames=('other.invalid',), ip_addresses=())
    assert x509.load_pem_x509_certificate(other).issuer == \
        x509.load_pem_x509_certificate(simulator.cacerts_pem).subject


def test_injected_material_still_wins_over_the_chain():
    """Injecting a listener certificate under use_bootstrap_chain breaks the chain on purpose: a
    genuine CA/leaf mismatch is exactly the 503 ca_mismatch precondition."""
    from wazuh_testing.tools.https_server import generate_ca_certificate, generate_leaf_certificate

    unrelated_ca, unrelated_key = generate_ca_certificate(common_name='Unrelated CA')
    unrelated_leaf = generate_leaf_certificate(unrelated_ca, unrelated_key)

    simulator = RemotedSimulator(port=free_port(), use_bootstrap_chain=True)
    simulator.tls_certificate = unrelated_leaf

    assert simulator.tls_certificate_pem == unrelated_leaf[0]
    assert simulator.cacerts_signs_listener is False
    # The pin still names what is actually served, which is the invariant tests rely on.
    assert simulator.tls_pin == spki_pin(unrelated_leaf[0])


def test_both_pins_are_readable_before_start_and_stable_across_a_restart():
    """A token has to be minted from a pin before the agent runs, and a key that silently rotated
    across a restart would break pin-based tests in a way that looks like an agent bug."""
    simulator = RemotedSimulator(port=free_port(), use_bootstrap_chain=True)

    assert not simulator.running
    cacerts_pin, tls_pin = simulator.cacerts_pin, simulator.tls_pin
    assert len(cacerts_pin) == 43 and len(tls_pin) == 43

    simulator.start()
    try:
        assert (simulator.cacerts_pin, simulator.tls_pin) == (cacerts_pin, tls_pin)
    finally:
        simulator.destroy()

    simulator.start()
    try:
        assert (simulator.cacerts_pin, simulator.tls_pin) == (cacerts_pin, tls_pin)
    finally:
        simulator.destroy()


def test_a_client_anchored_on_the_cacerts_certificate_verifies_the_listener():
    """The whole point of the chained topology, over a real socket: pin the /cacerts body, trust
    nothing else, check the hostname, and connect."""
    simulator = RemotedSimulator(port=free_port(), use_bootstrap_chain=True)
    anchor = simulator.cacerts_pem  # As a token-minting test would read it: before start().
    simulator.start()

    try:
        context = anchored_context(anchor)
        assert context.verify_mode == ssl.CERT_REQUIRED
        assert context.check_hostname is True
        assert len(context.get_ca_certs()) == 1

        connection = http.client.HTTPSConnection('127.0.0.1', simulator.port, context=context,
                                                 timeout=10)
        # Any request will do: reaching HTTP at all is what proves the handshake verified.
        connection.request('POST', f'/{simulator.prefix}/control', body=b'{}')
        assert connection.getresponse().status in (200, 400, 401)
        connection.close()

        assert simulator.handshake_failures == []
    finally:
        simulator.destroy()


def test_the_default_topology_cannot_be_verified_against_the_cacerts_certificate():
    """The negative counterpart, and the reason the chained mode had to be added: a pin that
    matches proves the bytes, not that they can verify anything."""
    simulator = RemotedSimulator(port=free_port())
    anchor = simulator.cacerts_pem
    simulator.start()

    try:
        with pytest.raises(ssl.SSLCertVerificationError):
            http.client.HTTPSConnection('127.0.0.1', simulator.port,
                                        context=anchored_context(anchor),
                                        timeout=10).request('POST', '/control', body=b'{}')
    finally:
        simulator.destroy()


def test_the_certificate_controller_is_built_only_when_something_asks_for_it():
    """It is an RSA-4096 keygen wanted only by the mTLS gate, and the listener's material no
    longer comes from it."""
    simulator = RemotedSimulator(port=free_port())

    assert simulator._certificate_controller is None
    simulator.tls_pin, simulator.cacerts_pin  # Certificate material does not pull it in.
    assert simulator._certificate_controller is None

    assert simulator.certificate_controller.root_ca_cert is not None
    assert simulator._certificate_controller is not None


def test_a_refused_certificate_is_recorded_on_the_simulator_and_survives_shutdown():
    """A client that refuses the served certificate never reaches HTTP, so there is no request to
    find and no status to assert on. The handshake record is the only evidence it happened -- and
    it has to outlive the listener it happened on, or a restart-and-assert test loses it."""
    from wazuh_testing.tools.https_server import generate_ca_certificate

    simulator = RemotedSimulator(port=free_port(), use_bootstrap_chain=True)
    unrelated, _ = generate_ca_certificate(common_name='Unrelated CA')
    simulator.start()

    try:
        with pytest.raises(ssl.SSLCertVerificationError):
            http.client.HTTPSConnection('127.0.0.1', simulator.port,
                                        context=anchored_context(unrelated),
                                        timeout=10).request('POST', '/control', body=b'{}')

        deadline = time.time() + 5
        while not simulator.handshake_failures and time.time() < deadline:
            time.sleep(0.05)
        assert simulator.handshake_failure_count == 1
        assert simulator.handshake_failures[0]['reason'] == 'TLSV1_ALERT_UNKNOWN_CA'
    finally:
        simulator.shutdown()

    # Still readable once the listener is gone.
    assert simulator.handshake_failure_count == 1

    simulator.clear()
    assert simulator.handshake_failures == []


def test_injecting_a_certificate_after_reading_a_pin_still_takes_effect():
    """Regression: reading cacerts_pem used to mint BOTH sides, so a tls_certificate assigned
    afterwards was silently ignored and the listener kept serving the original leaf. The two
    sides are minted independently now, because signing a leaf with cacerts_key_pem necessarily
    reads the CA first -- so that ordering has to work, not be a trap."""
    from wazuh_testing.tools.https_server import generate_leaf_certificate

    simulator = RemotedSimulator(port=free_port(), use_bootstrap_chain=True)
    original = simulator.tls_certificate_pem
    # Reads (and so mints) the CA, which is what used to lock the listener's material in.
    wrong_name = generate_leaf_certificate(simulator.cacerts_pem, simulator.cacerts_key_pem,
                                           hostnames=('other.invalid',), ip_addresses=())
    authority_before = simulator.cacerts_pem

    simulator.tls_certificate = wrong_name

    assert simulator.tls_certificate_pem == wrong_name[0]
    assert simulator.tls_certificate_pem != original
    # And the CA was NOT regenerated underneath the leaf just signed with it -- which would
    # leave the listener serving something the anchor cannot vouch for.
    assert simulator.cacerts_pem == authority_before
    assert simulator.cacerts_signs_listener is True


def test_injecting_a_cacerts_certificate_leaves_the_listener_alone():
    """The mirror image: replacing the handed-out CA must not silently re-mint the leaf."""
    from wazuh_testing.tools.https_server import generate_ca_certificate

    simulator = RemotedSimulator(port=free_port(), use_bootstrap_chain=True)
    listener_before = simulator.tls_certificate_pem
    unrelated, _ = generate_ca_certificate(common_name='Unrelated CA')

    simulator.cacerts_certificate = unrelated

    assert simulator.cacerts_pem == unrelated
    assert simulator.tls_certificate_pem == listener_before
    # An injected CA has no key here, so it cannot have signed anything -- a mismatch fixture.
    assert simulator.cacerts_key_pem is None
    assert simulator.cacerts_signs_listener is False
