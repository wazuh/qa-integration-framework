"""
Copyright (C) 2015-2026, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

Unit tests for RemotedSimulator's ``POST /enroll`` authentication and its ``401`` classes.

Three credentials share one bearer format and one endpoint, and the manager answers a refusal
with a *class* that tells the agent what the refusal cost it (agent-api.yaml, ``AuthFailureClass``):

    unknown_agent               re-enroll -- the identity is gone
    invalid_signature           do NOT re-enroll -- the credential is at fault, not the identity
    stale_token                 fix the clock and retry
    invalid_request             nothing usable was presented
    token_unknown/_expired/_revoked   the enrollment token's own state
    enrollment_key_unavailable  the manager could not judge it at all; retry later

Before wazuh/wazuh#39064 the agent re-enrolled on *any* 401, so the distinction did not exist on
the wire and this simulator sent one indistinguishable refusal. It now has to make every one of
these separately reachable, because the whole of that issue's agent-side policy is a branch on
this value -- and a policy nothing can drive is a policy nothing tests.

What is asserted here is the manager contract, not an agent's reaction to it: the status, the
envelope shape (``/enroll`` nests its error, every other route does not), the ``WWW-Authenticate``
challenge, and which class each distinct failure produces.

Run with:  PYTHONPATH=src python3 -m pytest tests/unit/test_enroll_authentication.py -v
"""
import hashlib
import http.client
import json
import time

import pytest

from conftest import unverified_context
from wazuh_testing.utils import jwt_enroll
from wazuh_testing.tools.simulators.remoted_simulator import (AUTH_ERROR_MESSAGE,
                                                              AUTH_FAILURE_CLASSES,
                                                              DEFAULT_REJECT_AUTH_CLASS,
                                                              ENROLL_ONLY_AUTH_CLASSES,
                                                              www_authenticate_challenge)

PASSWORD = 'MyEnrollmentSecret123'
TOKEN_ID = bytes(range(16))
TOKEN_SECRET = bytes(range(16, 32))
TOKEN_KID = jwt_enroll.b64url_encode(TOKEN_ID)


def enroll(simulator, body=None, bearer=None, protocol_version='1'):
    """POST /enroll against a running simulator. Returns (status, parsed body, headers)."""
    payload = json.dumps({'name': 'agent', 'version': '5.0.0'} if body is None else body).encode()
    headers = {'Content-Type': 'application/json'}
    if protocol_version is not None:
        headers['protocol-version'] = protocol_version
    if bearer is not None:
        headers['Authorization'] = f'Bearer {bearer}'

    connection = http.client.HTTPSConnection('127.0.0.1', simulator.port, timeout=10,
                                             context=unverified_context())
    try:
        target = f'/{simulator.prefix}/enroll' if simulator.prefix else '/enroll'
        connection.request('POST', target, body=payload, headers=headers)
        response = connection.getresponse()
        raw = response.read()
        return response.status, json.loads(raw or b'{}'), dict(response.getheaders())
    finally:
        connection.close()


def control(simulator, agent_id=None):
    """POST /control startup against a running simulator. Returns (status, parsed body, headers)."""
    connection = http.client.HTTPSConnection('127.0.0.1', simulator.port, timeout=10,
                                             context=unverified_context())
    try:
        target = f'/{simulator.prefix}/control' if simulator.prefix else '/control'
        connection.request('POST', target, body=json.dumps({'type': 'startup'}).encode(),
                           headers={'Content-Type': 'application/json', 'protocol-version': '1'})
        response = connection.getresponse()
        raw = response.read()
        return response.status, json.loads(raw or b'{}'), dict(response.getheaders())
    finally:
        connection.close()


@pytest.fixture()
def simulator(simulator_factory):
    """A started, open-mode simulator."""
    instance = simulator_factory()
    instance.start()
    return instance


def assert_enroll_refused(status, body, headers, failure_class):
    """A /enroll 401 names its class in the NESTED envelope and in the challenge."""
    assert status == 401
    assert body == {'error': {'code': failure_class, 'message': AUTH_ERROR_MESSAGE}}
    assert headers['WWW-Authenticate'] == www_authenticate_challenge(failure_class)


# ------------------------------------------------------------------ the password credential

def test_an_open_manager_enrolls_an_agent_that_presents_nothing(simulator):
    """The default instance: no password, no certificate, no bearer."""
    status, body, _ = enroll(simulator)
    assert status == 200
    assert body['id'] and body['key']


def test_a_password_manager_refuses_a_request_with_no_bearer(simulator_factory):
    instance = simulator_factory()
    instance.enroll_password = PASSWORD
    instance.start()

    status, body, headers = enroll(instance)
    assert_enroll_refused(status, body, headers, 'invalid_request')
    # `invalid_request` is the one class that reports no error_description: there is no
    # credential to have a verdict about.
    assert headers['WWW-Authenticate'] == 'Bearer error="invalid_request"'


def test_a_password_manager_accepts_the_right_bearer(simulator_factory):
    instance = simulator_factory()
    instance.enroll_password = PASSWORD
    instance.start()

    bearer = jwt_enroll.sign(jwt_enroll.derive_password_key(PASSWORD))
    status, body, _ = enroll(instance, bearer=bearer)
    assert status == 200
    assert body['id']


def test_the_wrong_password_is_an_invalid_signature(simulator_factory):
    instance = simulator_factory()
    instance.enroll_password = PASSWORD
    instance.start()

    bearer = jwt_enroll.sign(jwt_enroll.derive_password_key('WrongPassword'))
    assert_enroll_refused(*enroll(instance, bearer=bearer), 'invalid_signature')


def test_a_bearer_outside_the_window_is_stale_not_invalid(simulator_factory):
    """The agent corrects its clock from the Date header and retries; it must not re-enroll."""
    instance = simulator_factory()
    instance.enroll_password = PASSWORD
    instance.start()

    stale = jwt_enroll.sign(jwt_enroll.derive_password_key(PASSWORD), int(time.time()) - 3600)
    assert_enroll_refused(*enroll(instance, bearer=stale), 'stale_token')


@pytest.mark.parametrize('bearer', ['', 'garbage', 'a.b.c'], ids=['empty', 'garbage', 'three-segments'])
def test_a_bearer_that_is_not_this_profile_is_an_invalid_signature(simulator_factory, bearer):
    """Not a class of its own: the manager reports a malformed bearer exactly as it reports a
    badly signed one, and the agent must react to both the same way."""
    instance = simulator_factory()
    instance.enroll_password = PASSWORD
    instance.start()

    assert_enroll_refused(*enroll(instance, bearer=bearer), 'invalid_signature')


def test_an_unreadable_password_is_never_a_verdict_about_the_credential(simulator_factory):
    """`enrollment_key_unavailable` gets a BARE challenge: naming a class would claim a decision
    the manager never made."""
    instance = simulator_factory()
    instance.enroll_password = PASSWORD
    instance.enrollment_key_unavailable = True
    instance.start()

    bearer = jwt_enroll.sign(jwt_enroll.derive_password_key(PASSWORD))
    status, body, headers = enroll(instance, bearer=bearer)
    assert_enroll_refused(status, body, headers, 'enrollment_key_unavailable')
    assert headers['WWW-Authenticate'] == 'Bearer'


def test_an_open_manager_ignores_a_password_bearer(simulator):
    """There is no password to judge it against, and the manager would not be in Password mode."""
    status, _, _ = enroll(simulator, bearer=jwt_enroll.sign(jwt_enroll.derive_password_key(PASSWORD)))
    assert status == 200


# ------------------------------------------------------------------ the enrollment token

def test_a_registered_token_enrolls_in_any_mode(simulator):
    """Checked even on an open instance: the token names a key the password gate knows nothing of."""
    kid = simulator.register_enrollment_token(TOKEN_ID, TOKEN_SECRET)
    assert kid == TOKEN_KID

    bearer = jwt_enroll.sign(jwt_enroll.derive_token_key(TOKEN_SECRET), kid=kid)
    status, body, _ = enroll(simulator, bearer=bearer)
    assert status == 200
    assert body['id']


def test_an_unregistered_token_id_is_token_unknown(simulator):
    bearer = jwt_enroll.sign(jwt_enroll.derive_token_key(TOKEN_SECRET), kid=TOKEN_KID)
    assert_enroll_refused(*enroll(simulator, bearer=bearer), 'token_unknown')


def test_the_wrong_token_secret_is_an_invalid_signature(simulator):
    simulator.register_enrollment_token(TOKEN_ID, TOKEN_SECRET)
    bearer = jwt_enroll.sign(jwt_enroll.derive_token_key(bytes(16)), kid=TOKEN_KID)
    assert_enroll_refused(*enroll(simulator, bearer=bearer), 'invalid_signature')


@pytest.mark.parametrize('state, failure_class', [('expired', 'token_expired'), ('revoked', 'token_revoked')])
def test_a_correctly_signed_bearer_for_a_lapsed_token_reports_the_tokens_state(simulator, state, failure_class):
    """The signature is good and the state is still fatal -- a different situation from an id
    that was never registered, and one the agent must not answer by re-enrolling."""
    simulator.register_enrollment_token(TOKEN_ID, TOKEN_SECRET, state=state)
    bearer = jwt_enroll.sign(jwt_enroll.derive_token_key(TOKEN_SECRET), kid=TOKEN_KID)
    assert_enroll_refused(*enroll(simulator, bearer=bearer), failure_class)


def test_a_minted_token_is_one_this_instance_accepts(simulator_factory):
    """Minting used to register nothing, so a token minted for an instance was one it refused."""
    instance = simulator_factory()
    instance.mint_enrollment_token(credential=(TOKEN_ID, TOKEN_SECRET))
    instance.start()

    bearer = jwt_enroll.sign(jwt_enroll.derive_token_key(TOKEN_SECRET), kid=TOKEN_KID)
    assert enroll(instance, bearer=bearer)[0] == 200


def test_a_token_can_be_minted_already_revoked(simulator_factory):
    instance = simulator_factory()
    instance.mint_enrollment_token(credential=(TOKEN_ID, TOKEN_SECRET), state='revoked')
    instance.start()

    bearer = jwt_enroll.sign(jwt_enroll.derive_token_key(TOKEN_SECRET), kid=TOKEN_KID)
    assert_enroll_refused(*enroll(instance, bearer=bearer), 'token_revoked')


@pytest.mark.parametrize('token_id, secret, state', [
    (bytes(15), TOKEN_SECRET, 'valid'),
    (TOKEN_ID, bytes(17), 'valid'),
    (TOKEN_ID, TOKEN_SECRET, 'lapsed'),
], ids=['short-id', 'long-secret', 'unknown-state'])
def test_registering_an_impossible_token_is_refused(simulator_factory, token_id, secret, state):
    with pytest.raises(ValueError):
        simulator_factory().register_enrollment_token(token_id, secret, state=state)


# ------------------------------------------------------------------ authd's 403s

@pytest.mark.parametrize('forced, code, message', [
    ('authd_token_not_found', 9022, 'Enrollment token not found or revoked'),
    ('authd_token_expired', 9023, 'Enrollment token expired'),
    ('authd_token_exhausted', 9024, 'Enrollment token uses exhausted'),
])
def test_authds_verdict_on_a_verified_token_is_a_403_with_its_numeric_code(simulator, forced, code, message):
    """403 and not 401 precisely because the bearer DID verify: re-signing fixes nothing, so the
    agent has to stop rather than retry, and the numeric code is authd's own."""
    simulator.register_enrollment_token(TOKEN_ID, TOKEN_SECRET)
    simulator.enroll_force_error = forced

    bearer = jwt_enroll.sign(jwt_enroll.derive_token_key(TOKEN_SECRET), kid=TOKEN_KID)
    status, body, _ = enroll(simulator, bearer=bearer)
    assert status == 403
    assert body == {'error': {'code': code, 'message': message}}


def test_a_disabled_manager_answers_403_with_code_zero(simulator):
    """The other 403: administratively disabled, which is not a verdict about any credential."""
    simulator.enroll_force_error = 'disabled'
    status, body, _ = enroll(simulator)
    assert status == 403
    assert body == {'error': {'code': 0, 'message': 'Enrollment is disabled on this manager'}}


# ------------------------------------------------------------------ re-enrollment

def test_an_enrollment_hands_back_a_reenroll_secret(simulator):
    status, body, _ = enroll(simulator)
    assert status == 200
    assert len(body['reenroll_secret']) == 64
    assert simulator.reenroll_secret_for(body['id']) == body['reenroll_secret']


def test_a_manager_that_does_not_do_reenrollment_omits_the_field_entirely(simulator_factory):
    """Omitted, never null: the agent reads the field's ABSENCE as 'keep the enrollment
    password', and a null would be a malformed response instead."""
    instance = simulator_factory()
    instance.issue_reenroll_secret = False
    instance.start()

    status, body, _ = enroll(instance)
    assert status == 200
    assert 'reenroll_secret' not in body


def test_re_enrolling_with_the_secret_keeps_the_id_and_rotates_both_credentials(simulator):
    first = enroll(simulator)[1]

    bearer = jwt_enroll.sign(jwt_enroll.derive_reenroll_key(first['reenroll_secret']),
                             kid=jwt_enroll.canonical_agent_id(first['id']))
    status, second, _ = enroll(simulator, bearer=bearer)

    assert status == 200
    assert second['id'] == first['id']
    assert second['key'] != first['key']
    assert second['reenroll_secret'] != first['reenroll_secret']


def test_the_previous_secret_stops_working_the_moment_it_is_used(simulator):
    """Rotation is what keeps a captured response from being replayable forever."""
    first = enroll(simulator)[1]
    kid = jwt_enroll.canonical_agent_id(first['id'])
    old_key = jwt_enroll.derive_reenroll_key(first['reenroll_secret'])

    assert enroll(simulator, bearer=jwt_enroll.sign(old_key, kid=kid))[0] == 200
    assert_enroll_refused(*enroll(simulator, bearer=jwt_enroll.sign(old_key, kid=kid)), 'invalid_signature')


def test_an_id_this_manager_never_issued_is_unknown_agent(simulator):
    """authd's 9026, and the ONLY refusal that costs an agent its identity."""
    bearer = jwt_enroll.sign(jwt_enroll.derive_reenroll_key('ab' * 32), kid='001')
    assert_enroll_refused(*enroll(simulator, bearer=bearer), 'unknown_agent')


def test_a_purged_agent_is_unknown_agent_rather_than_a_bad_signature(simulator):
    """The distinction the whole policy rests on: forgetting the agent must not look like a
    credential problem, or the agent would keep the identity it no longer has."""
    first = enroll(simulator)[1]
    simulator.clear()

    bearer = jwt_enroll.sign(jwt_enroll.derive_reenroll_key(first['reenroll_secret']),
                             kid=jwt_enroll.canonical_agent_id(first['id']))
    assert_enroll_refused(*enroll(simulator, bearer=bearer), 'unknown_agent')


def test_the_wrong_secret_for_a_known_agent_is_an_invalid_signature(simulator):
    """authd's 9027. Not unknown_agent: the identity is fine, the credential is not, and
    re-enrolling would throw away a working identity."""
    first = enroll(simulator)[1]
    bearer = jwt_enroll.sign(jwt_enroll.derive_reenroll_key('cd' * 32),
                             kid=jwt_enroll.canonical_agent_id(first['id']))
    assert_enroll_refused(*enroll(simulator, bearer=bearer), 'invalid_signature')


def test_a_skewed_re_enrollment_is_stale_not_unknown(simulator):
    """authd's 9028. An agent whose clock is wrong must fix the clock, not its identity."""
    first = enroll(simulator)[1]
    bearer = jwt_enroll.sign(jwt_enroll.derive_reenroll_key(first['reenroll_secret']),
                             int(time.time()) - 3600,
                             kid=jwt_enroll.canonical_agent_id(first['id']))
    assert_enroll_refused(*enroll(simulator, bearer=bearer), 'stale_token')


def test_a_re_enrollment_bearer_outranks_a_key_hash(simulator):
    """A verified bearer is a stronger statement than a hash the agent computed over its own
    file, so it decides the id -- and, unlike the key_hash path, rotates the key."""
    first = enroll(simulator)[1]
    kid = jwt_enroll.canonical_agent_id(first['id'])
    other = enroll(simulator)[1]

    stale_hash = hashlib.sha1(f"{other['id']}agent{other['key']}".encode()).hexdigest()
    bearer = jwt_enroll.sign(jwt_enroll.derive_reenroll_key(first['reenroll_secret']), kid=kid)

    status, body, _ = enroll(simulator, {'name': 'agent', 'version': '5.0.0', 'key_hash': stale_hash},
                             bearer=bearer)
    assert status == 200
    assert body['id'] == first['id']
    assert body['key'] != first['key']


# ------------------------------------------------------------------ forced classes

@pytest.mark.parametrize('failure_class', AUTH_FAILURE_CLASSES)
def test_every_class_is_forceable_on_enroll(simulator, failure_class):
    """All eight, on an OPEN instance: forcing is checked before any credential is examined, so
    a test does not have to arrange the underlying failure to drive the agent's policy."""
    simulator.enroll_force_auth_class = failure_class
    assert_enroll_refused(*enroll(simulator), failure_class)


@pytest.mark.parametrize('failure_class',
                         [c for c in AUTH_FAILURE_CLASSES if c not in ENROLL_ONLY_AUTH_CLASSES])
def test_every_generic_class_is_forceable_on_the_other_routes(simulator_factory, failure_class):
    """The FLAT envelope here -- the two shapes really do differ, and the agent parses them with
    different code."""
    instance = simulator_factory(mode='REJECT_AUTH')
    instance.auth_force_class = failure_class
    instance.start()

    status, body, headers = control(instance)
    assert status == 401
    assert body == {'error': AUTH_ERROR_MESSAGE, 'code': failure_class}
    assert headers['WWW-Authenticate'] == www_authenticate_challenge(failure_class)


def test_reject_auth_names_unknown_agent_by_default(simulator_factory):
    """That mode exists to drive re-enrollment, and since #39064 a 401 the agent cannot classify
    deliberately does not cost it its identity -- so a classless REJECT_AUTH would leave every
    such test waiting for an enrollment that is never attempted."""
    instance = simulator_factory(mode='REJECT_AUTH')
    instance.start()

    status, body, _ = control(instance)
    assert status == 401
    assert body['code'] == DEFAULT_REJECT_AUTH_CLASS == 'unknown_agent'


@pytest.mark.parametrize('failure_class', ENROLL_ONLY_AUTH_CLASSES)
def test_an_enroll_only_class_cannot_be_forced_on_a_generic_route(simulator_factory, failure_class):
    """A generic route has no enrollment token and no enrollment password, so a real manager
    could not answer one of these on it."""
    with pytest.raises(ValueError):
        simulator_factory().auth_force_class = failure_class


@pytest.mark.parametrize('attribute', ['auth_force_class', 'enroll_force_auth_class'])
def test_an_unknown_class_is_refused(simulator_factory, attribute):
    instance = simulator_factory()
    with pytest.raises(ValueError):
        setattr(instance, attribute, 'not_a_class')
    setattr(instance, attribute, None)


def test_a_forced_class_is_not_consumed_after_one_request(simulator):
    """Unlike enroll_force_error: what is under test is what an agent does when a refusal KEEPS
    happening, which a one-shot knob cannot express."""
    simulator.enroll_force_auth_class = 'unknown_agent'
    for _ in range(3):
        assert enroll(simulator)[0] == 401


# ------------------------------------------------------------------ the protocol version

@pytest.mark.parametrize('version, expected', [
    (None, 'Missing required header: protocol-version'),
    ('2', 'Unsupported protocol-version'),
])
def test_the_protocol_version_is_a_400_not_an_authentication_outcome(simulator, version, expected):
    """Checked before anything else: the manager cannot judge a credential whose protocol
    version it does not know, so this is not a 401 at all."""
    status, body, _ = enroll(simulator, protocol_version=version)
    assert status == 400
    assert body == {'error': {'code': 0, 'message': expected}}
