"""
Copyright (C) 2015-2026, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

Unit tests for RemotedSimulator's GET /cacerts route.

The route hands out the CA an agent bootstraps trust from, and it is the one request in the whole
protocol that happens before anything can be verified. Its contract is the real manager's
(wazuh/wazuh: src/remoted/remoted_module/src/endpoints/cacertsEndpoint.cpp):

    200  application/x-pem-file, the file byte for byte -- a bundle is served as a bundle
    404  application/json, {"error":"not_found"}    -- missing, unreadable, or not a certificate
    503  application/json, {"error":"ca_mismatch"}  -- the CA does not sign what is served

Byte-exactness is the point of most of what follows: the agent copies the response into a fixed
char[8192] and then hashes it, so any normalisation this simulator applied would change the pin
and turn a correct agent into a failing one.

The route is served UNDER the configured prefix, like every other endpoint. That was contested
until wazuh/wazuh 3dd6af1638 routed the agent's fetch through prefixedTarget() after checking the
manager's own registration; before that the agent sent a bare /cacerts, which 404s against any
manager with a prefix -- which the shipped configuration has.

Run with:  PYTHONPATH=src python3 -m pytest tests/unit/test_cacerts_route.py -v
"""
import http.client
import ssl

import pytest

from conftest import anchored_context, unverified_context
from wazuh_testing.tools.simulators.remoted_simulator import (CACERTS_CA_MISMATCH_BODY,
                                                              CACERTS_CONTENT_TYPE,
                                                              CACERTS_NOT_FOUND_BODY, ENDPOINTS,
                                                              GET_ENDPOINTS, POST_ENDPOINTS,
                                                              spki_pin)


def request(simulator, path, method='GET', body=None, context=None):
    """Make one request against a running simulator. Returns (status, content_type, body, te)."""
    connection = http.client.HTTPSConnection(
        '127.0.0.1', simulator.port, timeout=10,
        context=context if context is not None else unverified_context())
    try:
        connection.request(method, path, body=body)
        response = connection.getresponse()
        return (response.status, response.getheader('Content-Type'), response.read(),
                response.getheader('Transfer-Encoding'))
    finally:
        connection.close()


def cacerts_path(simulator):
    """The prefixed target the agent actually sends."""
    return f'/{simulator.prefix}/cacerts' if simulator.prefix else '/cacerts'


# ---------------------------------------------------------------------------------------------
# The 200
# ---------------------------------------------------------------------------------------------

def test_cacerts_serves_the_pem_byte_for_byte_as_x_pem_file(simulator_factory):
    simulator = simulator_factory(use_bootstrap_chain=True)
    expected = simulator.cacerts_pem
    simulator.start()

    status, content_type, body, transfer_encoding = request(simulator, cacerts_path(simulator))

    assert status == 200
    assert content_type == CACERTS_CONTENT_TYPE
    # No re-encoding, no stripping, no trailing-newline fixup.
    assert body == expected
    # Content-Length, like the manager: the agent reads into a fixed buffer, and a
    # byte-comparing test should not have to de-chunk first.
    assert transfer_encoding is None


def test_the_served_body_pins_to_the_value_a_token_would_carry(simulator_factory):
    """The whole reason the route exists: what comes off the wire must hash to the pin the
    simulator advertised before it started, or a token minted from it is worthless."""
    simulator = simulator_factory(use_bootstrap_chain=True)
    advertised = simulator.cacerts_pin
    simulator.start()

    body = request(simulator, cacerts_path(simulator))[2]

    assert spki_pin(body) == advertised


def test_a_bundle_is_served_whole_and_pins_its_first_certificate(simulator_factory):
    """"A bundle is served as a bundle", and the pin names the FIRST certificate -- the same
    rule the agent's spkiSha256FromPem applies, so the two cannot disagree about which one."""
    from wazuh_testing.tools.https_server import generate_ca_certificate

    first, _ = generate_ca_certificate(common_name='First CA')
    second, _ = generate_ca_certificate(common_name='Second CA')
    simulator = simulator_factory()
    simulator.cacerts_certificate = first + second
    simulator.start()

    body = request(simulator, cacerts_path(simulator))[2]

    assert body == first + second
    assert body.count(b'-----BEGIN CERTIFICATE-----') == 2
    assert simulator.cacerts_pin == spki_pin(first)


def test_an_injected_certificate_is_the_one_actually_served(simulator_factory):
    """Promotes the injection hook from "reported by cacerts_pin" to "served on the wire"."""
    from wazuh_testing.tools.https_server import generate_ca_certificate

    chosen, _ = generate_ca_certificate(common_name='Chosen CA')
    simulator = simulator_factory()
    simulator.cacerts_certificate = chosen
    simulator.start()

    assert request(simulator, cacerts_path(simulator))[2] == chosen
    assert simulator.cacerts_pin == spki_pin(chosen)


def test_the_fetch_needs_no_verification_no_authorization_and_no_client_certificate(
        simulator_factory):
    """It is the request that precedes trust, so nothing it could authenticate with exists."""
    simulator = simulator_factory(use_bootstrap_chain=True)
    simulator.start()

    status = request(simulator, cacerts_path(simulator), context=unverified_context())[0]

    assert status == 200
    recorded = simulator.last_request('/cacerts')
    assert recorded['method'] == 'GET'
    assert recorded['body'] == b''
    assert 'Authorization' not in recorded['headers']
    assert 'protocol-version' not in recorded['headers']
    assert recorded['tls']['peer_certificate'] is None


def test_the_route_is_reachable_on_a_verified_connection_too(simulator_factory):
    """Nothing about it requires an unverified connection -- an agent re-fetching after it has
    an anchor gets the same answer."""
    simulator = simulator_factory(use_bootstrap_chain=True)
    anchor = simulator.cacerts_pem
    simulator.start()

    assert request(simulator, cacerts_path(simulator),
                   context=anchored_context(anchor))[0] == 200


# ---------------------------------------------------------------------------------------------
# Routing
# ---------------------------------------------------------------------------------------------

def test_cacerts_is_served_under_the_configured_prefix(simulator_factory):
    """Settled by wazuh/wazuh 3dd6af1638: the agent folds the prefix in via prefixedTarget(),
    matching the manager, which registers /cacerts under global_prefix like every route."""
    simulator = simulator_factory(use_bootstrap_chain=True)
    assert simulator.prefix == 'wazuh-manager'
    simulator.start()

    assert request(simulator, '/wazuh-manager/cacerts')[0] == 200


def test_a_bare_cacerts_target_is_not_routed_under_a_prefix(simulator_factory):
    """The failure the agent used to walk into: an unprefixed fetch against a manager with a
    prefix 404s, before the pin comparison it was heading for ever runs."""
    simulator = simulator_factory(use_bootstrap_chain=True)
    simulator.start()

    status, content_type, body, _ = request(simulator, '/cacerts')

    assert status == 404
    assert content_type == 'application/json'
    assert body == CACERTS_NOT_FOUND_BODY
    # Recorded anyway, so the mistake is visible rather than being a mystery 404.
    assert simulator.last_request('/cacerts')['path'] == '/cacerts'


def test_cacerts_is_served_at_bare_root_when_no_prefix_is_configured(simulator_factory):
    simulator = simulator_factory(prefix='', use_bootstrap_chain=True)
    simulator.start()

    assert request(simulator, '/cacerts')[0] == 200
    # And the prefixed spelling is the one that misses now.
    assert request(simulator, '/wazuh-manager/cacerts')[0] == 404


def test_a_post_to_cacerts_is_not_routed(simulator_factory):
    """The manager's router matches method and path together, so a GET-only route falls through
    to the transport's not_found handler rather than answering 405."""
    simulator = simulator_factory(use_bootstrap_chain=True)
    simulator.start()

    assert request(simulator, cacerts_path(simulator), method='POST', body=b'{}')[0] == 404


def test_an_unknown_get_target_is_the_transports_not_found(simulator_factory):
    simulator = simulator_factory(use_bootstrap_chain=True)
    simulator.start()

    status, content_type, body, _ = request(simulator, f'/{simulator.prefix}/nope')

    assert (status, content_type, body) == (404, 'application/json', CACERTS_NOT_FOUND_BODY)


def test_cacerts_is_not_a_member_of_the_post_endpoint_set():
    """If it were, POST /cacerts would resolve, survive fault injection and auth, and reach
    do_POST's final else branch -- whose comment claims to be unreachable."""
    assert '/cacerts' not in ENDPOINTS
    assert '/cacerts' not in POST_ENDPOINTS
    assert GET_ENDPOINTS == ('/cacerts',)
    assert POST_ENDPOINTS is ENDPOINTS


def test_resolve_endpoint_still_defaults_to_the_post_set(simulator_factory):
    """The method parameter is defaulted so every existing caller keeps working."""
    simulator = simulator_factory()

    assert simulator.resolve_endpoint('/wazuh-manager/control') == '/control'
    assert simulator.resolve_endpoint('/wazuh-manager/cacerts') is None
    assert simulator.resolve_endpoint('/wazuh-manager/cacerts', method='GET') == '/cacerts'
    # Query strings are stripped on both paths.
    assert simulator.resolve_endpoint('/wazuh-manager/cacerts?x=1', method='GET') == '/cacerts'


# ---------------------------------------------------------------------------------------------
# Failure modes
# ---------------------------------------------------------------------------------------------

@pytest.mark.parametrize('outcome,status,body', [
    ('not_found', 404, CACERTS_NOT_FOUND_BODY),
    ('ca_mismatch', 503, CACERTS_CA_MISMATCH_BODY),
])
def test_a_forced_error_reproduces_the_managers_exact_body(simulator_factory, outcome, status,
                                                           body):
    """Byte-compared on purpose. json.dumps would emit {"error": "not_found"} with a space,
    where the manager emits none."""
    simulator = simulator_factory(use_bootstrap_chain=True)
    simulator.cacerts_force_error = outcome
    simulator.start()

    assert request(simulator, cacerts_path(simulator))[:3] == (status, 'application/json', body)


def test_a_forced_error_persists_across_requests(simulator_factory):
    """A manager whose CA is unreadable stays that way; this is not a one-shot like
    enroll_force_error."""
    simulator = simulator_factory(use_bootstrap_chain=True)
    simulator.cacerts_force_error = 'not_found'
    simulator.start()

    assert request(simulator, cacerts_path(simulator))[0] == 404
    assert request(simulator, cacerts_path(simulator))[0] == 404

    simulator.cacerts_force_error = None
    assert request(simulator, cacerts_path(simulator))[0] == 200


def test_an_unknown_forced_error_is_rejected_at_assignment(simulator_factory):
    simulator = simulator_factory()

    with pytest.raises(ValueError, match='cacerts_force_error'):
        simulator.cacerts_force_error = 'teapot'


def test_material_that_is_not_a_certificate_is_a_404(simulator_factory):
    """The manager's own rule -- no BEGIN CERTIFICATE block means not_found -- so an operator
    pointing ca_certificate at a key file, or at nothing, needs no extra switch to express."""
    simulator = simulator_factory()
    simulator.cacerts_certificate = b'-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n'
    simulator.start()

    assert request(simulator, cacerts_path(simulator))[:3] == (404, 'application/json',
                                                               CACERTS_NOT_FOUND_BODY)


def test_an_empty_body_is_a_404_and_has_no_pin(simulator_factory):
    simulator = simulator_factory()
    simulator.cacerts_certificate = b''
    simulator.start()

    assert request(simulator, cacerts_path(simulator))[0] == 404
    # Raises rather than returning None: a silent None would flow into a minted token.
    with pytest.raises(Exception):
        simulator.cacerts_pin


@pytest.mark.parametrize('mode', ['REJECT_AUTH', 'SERVICE_UNAVAILABLE', 'BAD_REQUEST',
                                  'PAYLOAD_TOO_LARGE'])
def test_the_fault_injection_modes_do_not_touch_cacerts(simulator_factory, mode):
    """Surprising but correct: the manager registers this route with no auth gateway and outside
    the in-flight byte budget, and its handler ignores the request entirely. A trust bootstrap
    must not be shed under memory pressure. Script its failures with cacerts_force_error."""
    simulator = simulator_factory(mode=mode, use_bootstrap_chain=True)
    simulator.start()

    assert request(simulator, cacerts_path(simulator))[0] == 200
    # While a POST endpoint on the same instance does feel the mode.
    assert request(simulator, f'/{simulator.prefix}/control', method='POST',
                   body=b'{"type":"startup"}')[0] != 200


def test_mtls_makes_the_bootstrap_unreachable_which_is_what_the_manager_does_too(
        simulator_factory):
    """Not a simulator limitation. A manager with remote.https.verification_mode
    certificate|full sets verify_peer|verify_fail_if_no_peer_cert on the listener, and /cacerts
    is registered on that same listener -- so the unauthenticated bootstrap genuinely cannot
    happen there either. There is no HTTP status for it: assert on the handshake record."""
    simulator = simulator_factory(use_bootstrap_chain=True)
    simulator.require_client_cert = True
    simulator.start()

    with pytest.raises(ssl.SSLError):
        request(simulator, cacerts_path(simulator))

    assert simulator.get_requests('/cacerts') == []
    assert simulator.handshake_failure_count >= 1
