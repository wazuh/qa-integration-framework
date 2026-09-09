"""
Copyright (C) 2015-2026, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

End-to-end tests for the enrollment-token bootstrap, driven by the reference client.

This is the only place the whole flow runs: token -> unverified GET /cacerts -> SPKI pin compare
-> fully verified reconnect -> POST /enroll -> POST /control. The agent cannot be driven through
it yet (hc_fetch_cacerts has no production caller and the installer discards the pin), so these
tests establish that the manager side can host the flow, and stand as the executable specification
the agent-side wiring has to satisfy.

Read the negative cases as the substance of the file rather than as extras. Two in particular say
something the happy path cannot:

- A mismatched pin must stop the client BEFORE it reconnects. Asserting only that the client
  raised would pass even if it had enrolled first, so these assert on what the manager received.
- A pin that MATCHES a CA which cannot verify the listener must still fail. That is the executable
  form of the pin primitive's own scope note: a matching pin proves the bytes, not that they can
  vouch for anything.

Run with:  PYTHONPATH=src python3 -m pytest tests/unit/test_bootstrap_reference_client.py -v
"""
import ssl

import pytest

from conftest import wait_until
from wazuh_testing.tools.bootstrap_client import (BOOTSTRAP_REASONS, BootstrapError,
                                                  EnrollmentBootstrapClient)
from wazuh_testing.tools.https_server import generate_ca_certificate, generate_leaf_certificate
from wazuh_testing.utils.enrollment_token import decode_token, encode_raw, encode_token


def paths(simulator):
    """The request targets the simulator saw, in arrival order."""
    return [request['path'] for request in simulator.requests]


def methods_and_paths(simulator):
    return [(request['method'], request['path']) for request in simulator.requests]


# ---------------------------------------------------------------------------------------------
# The happy path
# ---------------------------------------------------------------------------------------------

def test_the_whole_bootstrap_completes_from_a_token_alone(simulator_factory):
    """verify_auth is on and there is no client.keys file anywhere: the /control signature uses a
    key that exists only in the manager's memory, which is what proves the enrollment was real
    and immediately usable."""
    simulator = simulator_factory(use_bootstrap_chain=True, verify_auth=True)
    token = simulator.mint_enrollment_token()
    simulator.start()

    result = EnrollmentBootstrapClient(token, agent_name='ref-agent').run()

    assert result.cacerts_status == 200
    assert result.cacerts_content_type == 'application/x-pem-file'
    assert result.ca_pem == simulator.cacerts_pem
    assert result.ca_pin == simulator.cacerts_pin
    assert result.enroll['name'] == 'ref-agent'
    assert result.enroll['id'] and result.enroll['key']
    assert result.startup == simulator.startup_response()
    # In this order, and only these: one fetch, one enrollment, one startup.
    assert methods_and_paths(simulator) == [
        ('GET', '/wazuh-manager/cacerts'),
        ('POST', '/wazuh-manager/enroll'),
        ('POST', '/wazuh-manager/control'),
    ]
    assert simulator.handshake_failure_count == 0


def test_every_leg_is_addressed_under_the_prefix_the_token_carries(simulator_factory):
    """Including /cacerts, since wazuh/wazuh 3dd6af1638. Nothing but the token tells the client
    what the prefix is."""
    simulator = simulator_factory(prefix='gateway/wazuh-manager', use_bootstrap_chain=True)
    token = simulator.mint_enrollment_token()
    simulator.start()

    EnrollmentBootstrapClient(token, agent_name='a').run()

    assert paths(simulator) == ['/gateway/wazuh-manager/cacerts',
                               '/gateway/wazuh-manager/enroll',
                               '/gateway/wazuh-manager/control']


def test_the_bootstrap_completes_against_a_bare_root_manager(simulator_factory):
    """The one normalisation rule a round trip cannot catch: a bare-root manager's adr has to be
    written 'host/', because a bare 'host' means the DEFAULT prefix."""
    simulator = simulator_factory(prefix='', use_bootstrap_chain=True, verify_auth=True)
    token = simulator.mint_enrollment_token()
    simulator.start()

    assert decode_token(token).adr.endswith('/')

    EnrollmentBootstrapClient(token, agent_name='a').run()

    assert paths(simulator) == ['/cacerts', '/enroll', '/control']


def test_the_client_is_driven_by_the_token_and_nothing_else(simulator_factory):
    """No host, port or prefix is passed in -- they come out of the token, which is what makes
    this a statement about the token's meaning."""
    simulator = simulator_factory(use_bootstrap_chain=True)
    simulator.start()

    client = EnrollmentBootstrapClient(simulator.mint_enrollment_token(), agent_name='a')

    assert (client.host, client.port, client.prefix) == ('127.0.0.1', simulator.port,
                                                         'wazuh-manager')


def test_the_two_legs_use_opposite_tls_postures(simulator_factory):
    """The fetch cannot verify (there is no anchor yet, by definition) and the reconnect must
    verify against the fetched certificate alone -- no system anchors, or the connection could
    succeed for reasons unrelated to the pin."""
    simulator = simulator_factory(use_bootstrap_chain=True)
    client = EnrollmentBootstrapClient(simulator.mint_enrollment_token(), agent_name='a')

    unverified = client.unverified_context
    assert unverified.verify_mode == ssl.CERT_NONE
    assert unverified.check_hostname is False

    verified = client.verified_context(simulator.cacerts_pem)
    assert verified.verify_mode == ssl.CERT_REQUIRED
    assert verified.check_hostname is True
    anchors = verified.get_ca_certs()
    assert len(anchors) == 1
    assert 'Wazuh Test Root CA' in str(anchors[0]['subject'])


def test_both_legs_floor_the_protocol_at_tls_1_3(simulator_factory):
    """Mirroring the agent's unconditional CURLOPT_SSLVERSION, which it sets even on the
    unverified fetch."""
    simulator = simulator_factory(use_bootstrap_chain=True)
    client = EnrollmentBootstrapClient(simulator.mint_enrollment_token(), agent_name='a')

    assert client.unverified_context.minimum_version == ssl.TLSVersion.TLSv1_3
    assert client.verified_context(simulator.cacerts_pem).minimum_version == \
        ssl.TLSVersion.TLSv1_3

    simulator.start()
    EnrollmentBootstrapClient(simulator.mint_enrollment_token(), agent_name='a').run()
    assert simulator.last_request('/cacerts')['tls']['version'] == 'TLSv1.3'


def test_the_fetch_carries_no_credential_of_any_kind(simulator_factory):
    simulator = simulator_factory(use_bootstrap_chain=True)
    token = simulator.mint_enrollment_token()
    simulator.start()

    EnrollmentBootstrapClient(token, agent_name='a').run()

    fetch = simulator.last_request('/cacerts')
    assert fetch['body'] == b''
    assert 'Authorization' not in fetch['headers']
    assert fetch['tls']['peer_certificate'] is None


def test_the_bootstrap_composes_with_the_enroll_password_gate(simulator_factory):
    simulator = simulator_factory(use_bootstrap_chain=True)
    simulator.enroll_password = 'the-password'
    token = simulator.mint_enrollment_token()
    simulator.start()

    result = EnrollmentBootstrapClient(token, agent_name='a',
                                       enroll_password='the-password').run()
    assert result.enroll['id']

    # And the gate is real: the same walk without the password stops at /enroll.
    simulator.clear()
    with pytest.raises(BootstrapError) as error:
        EnrollmentBootstrapClient(token, agent_name='b').run()
    assert error.value.reason == 'enroll_failed'


def test_a_token_carrying_the_certificate_itself_needs_no_fetch(simulator_factory):
    """The --embed-ca shape: the anchor travels in the token, so there is no pin to compare and
    the reconnect can be made straight away."""
    simulator = simulator_factory(use_bootstrap_chain=True)
    token = simulator.mint_enrollment_token(anchor='ca')
    simulator.start()

    decoded = decode_token(token)
    assert decoded.pin is None
    assert decoded.ca == simulator.cacerts_pem.decode()

    client = EnrollmentBootstrapClient(token, agent_name='a')
    connection = client.open_verified(decoded.ca.encode())
    try:
        assert client.enroll(connection)['id']
    finally:
        connection.close()
    assert simulator.get_requests('/cacerts') == []


# ---------------------------------------------------------------------------------------------
# The negatives
# ---------------------------------------------------------------------------------------------

def test_a_mismatched_pin_stops_the_client_before_it_reconnects(simulator_factory):
    """anchor='tls' pins the listener rather than the CA, so the pin is well-formed and names
    the wrong key. The second assertion is the one that matters: raising is not enough, the
    client must not have enrolled first."""
    simulator = simulator_factory(use_bootstrap_chain=True)
    token = simulator.mint_enrollment_token(anchor='tls')
    simulator.start()

    with pytest.raises(BootstrapError) as error:
        EnrollmentBootstrapClient(token, agent_name='a').run()

    assert error.value.reason == 'pin_mismatch'
    assert len(simulator.get_requests('/cacerts')) == 1   # Fetched once, no retry loop.
    assert simulator.get_requests('/enroll') == []        # And never came back.
    assert simulator.get_requests('/control') == []


def test_a_pin_naming_an_unrelated_certificate_is_a_mismatch(simulator_factory):
    unrelated, _ = generate_ca_certificate(common_name='Unrelated CA')
    simulator = simulator_factory(use_bootstrap_chain=True)
    from wazuh_testing.tools.simulators.remoted_simulator import spki_pin
    token = encode_token(simulator.enrollment_adr, pin=spki_pin(unrelated))
    simulator.start()

    with pytest.raises(BootstrapError) as error:
        EnrollmentBootstrapClient(token, agent_name='a').run()

    assert error.value.reason == 'pin_mismatch'
    assert simulator.get_requests('/enroll') == []


@pytest.mark.parametrize('pin', ['a' * 64, 'A' * 42, 'A' * 44])
def test_a_malformed_pin_is_refused_before_anything_is_sent(simulator_factory, pin):
    """A malformed pin is an unusable TOKEN, not a failed comparison, so it is caught by the
    decoder at construction and the client never opens a connection at all. That is the same
    layering the agent has -- it decodes before it fetches -- and it is why 'pin_malformed'
    is reachable only by calling check_pin() out of sequence (see below)."""
    simulator = simulator_factory(use_bootstrap_chain=True)
    token = encode_raw({'ver': 1, 'adr': simulator.enrollment_adr, 'pin': pin})
    simulator.start()

    with pytest.raises(BootstrapError) as error:
        EnrollmentBootstrapClient(token, agent_name='a').run()

    assert error.value.reason == 'token_invalid'
    # Stronger than "no enrollment": nothing was sent whatsoever.
    assert simulator.requests == []


def test_comparing_a_pin_on_a_ca_anchored_token_is_a_sequencing_error(simulator_factory):
    """The reachable pin_malformed: an --embed-ca token has no pin to compare, so a caller that
    fetches and compares anyway has the walk in the wrong order."""
    simulator = simulator_factory(use_bootstrap_chain=True)
    client = EnrollmentBootstrapClient(simulator.mint_enrollment_token(anchor='ca'),
                                       agent_name='a')

    with pytest.raises(BootstrapError) as error:
        client.check_pin(simulator.cacerts_pem)
    assert error.value.reason == 'pin_malformed'


def test_a_matching_pin_is_not_the_same_thing_as_trust(simulator_factory):
    """The executable form of the pin primitive's scope note, and the reason the chained topology
    had to exist. The default topology's /cacerts certificate is genuine and its pin matches
    exactly -- and it still cannot verify the listener, so the reconnect fails."""
    simulator = simulator_factory()                      # Two unrelated certificates.
    token = simulator.mint_enrollment_token()            # With the CORRECT cacerts pin.
    simulator.start()

    client = EnrollmentBootstrapClient(token, agent_name='a')
    status, _, ca_pem = client.fetch_cacerts()
    assert status == 200
    # The pin comparison passes.
    assert client.check_pin(ca_pem) == simulator.cacerts_pin

    # And the connection it was supposed to authorise does not.
    with pytest.raises(BootstrapError) as error:
        client.open_verified(ca_pem)
    assert error.value.reason == 'verified_connect_failed'
    assert simulator.get_requests('/enroll') == []


def test_a_certificate_for_a_different_name_fails_the_reconnect(simulator_factory):
    """Chains correctly to the pinned anchor, so path validation succeeds; only the name check
    fails. Signed with the anchor's own key, which was only possible once cacerts_key_pem
    stopped being discarded."""
    simulator = simulator_factory(use_bootstrap_chain=True)
    wrong_name = generate_leaf_certificate(simulator.cacerts_pem, simulator.cacerts_key_pem,
                                           hostnames=('other.invalid',), ip_addresses=())
    simulator.tls_certificate = wrong_name
    token = simulator.mint_enrollment_token()
    simulator.start()

    with pytest.raises(BootstrapError) as error:
        EnrollmentBootstrapClient(token, agent_name='a').run()

    assert error.value.reason == 'verified_connect_failed'
    # The fetch itself succeeded -- it does not verify anything -- so the failure is squarely
    # at the reconnect.
    assert len(simulator.get_requests('/cacerts')) == 1
    assert simulator.get_requests('/enroll') == []
    # The client's rejection reaches the listener as an alert, after the exception above has
    # already propagated -- so this has to be waited for, not read immediately.
    assert wait_until(lambda: simulator.handshake_failure_count >= 1)
    assert simulator.handshake_failures[-1]['reason'] == 'SSLV3_ALERT_BAD_CERTIFICATE'


@pytest.mark.parametrize('outcome,reason', [
    ('not_found', 'cacerts_http_error'),
    ('ca_mismatch', 'cacerts_http_error'),
])
def test_a_failing_cacerts_route_aborts_with_its_own_reason(simulator_factory, outcome, reason):
    simulator = simulator_factory(use_bootstrap_chain=True)
    simulator.cacerts_force_error = outcome
    token = simulator.mint_enrollment_token()
    simulator.start()

    with pytest.raises(BootstrapError) as error:
        EnrollmentBootstrapClient(token, agent_name='a').run()

    assert error.value.reason == reason
    assert simulator.get_requests('/enroll') == []


def test_a_cacerts_body_that_is_not_a_certificate_aborts_before_any_pin_work(
        simulator_factory):
    """The HTML-error-page case: a 200 whose body is not a PEM must not be hashed and compared
    as though it were."""
    simulator = simulator_factory(use_bootstrap_chain=True)
    token = simulator.mint_enrollment_token()
    simulator.start()

    client = EnrollmentBootstrapClient(token, agent_name='a')
    with pytest.raises(BootstrapError) as error:
        client.check_pin(b'<html><body>502 Bad Gateway</body></html>')
    assert error.value.reason == 'cacerts_not_pem'


def test_an_unprefixed_token_against_a_prefixed_manager_is_an_http_error(simulator_factory):
    """The concrete cost of getting the prefix wrong, which is why the agent's bare /cacerts was
    fixed: a 404 that an agent would otherwise report as an unreachable manager."""
    simulator = simulator_factory(use_bootstrap_chain=True)
    token = encode_token(f'127.0.0.1:{simulator.port}/', pin=simulator.cacerts_pin)
    simulator.start()

    with pytest.raises(BootstrapError) as error:
        EnrollmentBootstrapClient(token, agent_name='a').run()

    assert error.value.reason == 'cacerts_http_error'
    assert simulator.last_request('/cacerts')['path'] == '/cacerts'


def test_an_unreachable_manager_aborts_with_its_own_reason(simulator_factory):
    simulator = simulator_factory(use_bootstrap_chain=True)
    token = simulator.mint_enrollment_token()
    # Deliberately never started.

    with pytest.raises(BootstrapError) as error:
        EnrollmentBootstrapClient(token, agent_name='a', timeout=3).run()

    assert error.value.reason == 'unreachable'


def test_an_undecodable_token_is_refused_at_construction(simulator_factory):
    with pytest.raises(BootstrapError) as error:
        EnrollmentBootstrapClient('not-a-token!', agent_name='a')

    assert error.value.reason == 'token_invalid'


def test_every_reason_the_client_can_raise_is_declared():
    """Keeps BOOTSTRAP_REASONS honest, since it is the documented contract of the walk."""
    assert len(set(BOOTSTRAP_REASONS)) == len(BOOTSTRAP_REASONS)
    for reason in ('token_invalid', 'unreachable', 'cacerts_http_error', 'cacerts_not_pem',
                   'pin_malformed', 'pin_mismatch', 'verified_connect_failed', 'enroll_failed',
                   'startup_failed'):
        assert reason in BOOTSTRAP_REASONS
