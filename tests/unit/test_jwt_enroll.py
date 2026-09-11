"""
Copyright (C) 2015-2026, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

Unit tests for the ``wazuh-enroll+jwt`` bearer.

Every frozen vector below is copied from the profile's own oracle
(wazuh/wazuh: src/shared_modules/utils/jwt/testVectors.hpp, namespaces ``test_vectors::enroll``
and ``test_vectors::enroll_token``), which authd's C tests and the Go simulator pin too. That is
the point of the file: a bearer minted here is one a real manager accepts, and one refused here is
one it would refuse -- with the same reason, which matters because the manager turns
``INVALID_SIGNATURE`` and ``STALE_TOKEN`` into *different* 401 classes and the agent's
re-enrollment policy branches on them.

The negative matrix is deliberately shallower than the C++ one (jwtEnrollSignVerify_test.cpp
covers the grammar exhaustively): what is pinned here is what this simulator actually decides --
the three key derivations, the `kid` classification, the exact header and claim sets, and each
distinct verification verdict.

Run with:  PYTHONPATH=src python3 -m pytest tests/unit/test_jwt_enroll.py -v
"""
import pytest

from wazuh_testing.utils.jwt_enroll import (DEFAULT_CLOCK_SKEW_SEC, JTI_BYTES, KidKind,
                                            LIFETIME_SEC, MAX_TOKEN_BYTES, PeekedKid, VerifyError,
                                            b64url_encode, canonical_agent_id, classify_kid,
                                            derive_password_key, derive_reenroll_key,
                                            derive_token_key, header_json, is_canonical_agent_id,
                                            is_canonical_b64url_of, payload_json, peek_kid,
                                            random_jti, random_reenroll_secret, sign, verify)

# ---------------------------------------------------------------- frozen vectors

PASSWORD = 'MyEnrollmentSecret123'
PASSWORD_KEY_HEX = 'eeecc651648436211783381e38d0a661bfecc2888a4e23b28c94f415f98616b6'
IAT = 1700000000
NOW = IAT + 10
JTI = 'AAECAwQFBgcICQoLDA0ODw'

HEADER_JSON = '{"alg":"HS256","typ":"wazuh-enroll+jwt"}'
PAYLOAD_JSON = '{"exp":1700000060,"iat":1700000000,"jti":"AAECAwQFBgcICQoLDA0ODw","nbf":1700000000}'
TOKEN = ('eyJhbGciOiJIUzI1NiIsInR5cCI6IndhenVoLWVucm9sbCtqd3QifQ.'
         'eyJleHAiOjE3MDAwMDAwNjAsImlhdCI6MTcwMDAwMDAwMCwianRpIjoiQUFFQ0F3UUZCZ2NJQ1FvTERBME9EdyIsIm5iZiI6MTcwMDAwMDAwMH0.'
         'Ll9rqCc4D0emY3xUV99-yD-ep0Xp7CI1qKG8Rzkvm8o')

# Same claims, signed with the key of password "WrongPassword".
WRONG_PASSWORD_TOKEN = ('eyJhbGciOiJIUzI1NiIsInR5cCI6IndhenVoLWVucm9sbCtqd3QifQ.'
                        'eyJleHAiOjE3MDAwMDAwNjAsImlhdCI6MTcwMDAwMDAwMCwianRpIjoiQUFFQ0F3UUZCZ2NJQ1FvTERBME9EdyIsIm5iZiI6'
                        'MTcwMDAwMDAwMH0.'
                        'a8lxhFZIpYPD74vwYD_h6kPT4ZnedFOHEBMJPbltzZg')

# Correct password key and signature, but the header carries a `kid`: the shared-key form is an
# exact two-member header, so this must never verify against the password key.
KID_HEADER_TOKEN = ('eyJhbGciOiJIUzI1NiIsImtpZCI6IjAwMSIsInR5cCI6IndhenVoLWVucm9sbCtqd3QifQ.'
                    'eyJleHAiOjE3MDAwMDAwNjAsImlhdCI6MTcwMDAwMDAwMCwianRpIjoiQUFFQ0F3UUZCZ2NJQ1FvTERBME9EdyIsIm5iZiI6MTcw'
                    'MDAwMDAwMH0.'
                    '-PID3RuMlsz0ShaKX5IppGhP3iX2nEq6mfyGPgqDDMY')

TOKEN_SECRET_HEX = '101112131415161718191a1b1c1d1e1f'
TOKEN_KEY_HEX = '5da72b786a15757caa8d825a74a3474c3f15b048fd1064b49863ffc715a95860'
TOKEN_KID = 'AAECAwQFBgcICQoLDA0ODw'
TOKEN_KID_HEADER_JSON = '{"alg":"HS256","kid":"AAECAwQFBgcICQoLDA0ODw","typ":"wazuh-enroll+jwt"}'
TOKEN_KID_JWT = ('eyJhbGciOiJIUzI1NiIsImtpZCI6IkFBRUNBd1FGQmdjSUNRb0xEQTBPRHciLCJ0eXAiOiJ3YXp1aC1lbnJvbGwrand0In0.'
                 'eyJleHAiOjE3MDAwMDAwNjAsImlhdCI6MTcwMDAwMDAwMCwianRpIjoiQUFFQ0F3UUZCZ2NJQ1FvTERBME9EdyIsIm5iZiI6MTcwMDAw'
                 'MDAwMH0.'
                 '7sTfFRpPNoSg7QPO1h6FWCvY2Islau-E0gQnP1PWelk')

REENROLL_SECRET_HEX = '000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f'
REENROLL_KEY_HEX = '68b01ea65fc441951a17e3fd9b7e2dedc846d364f38596630ea3f69f60482ae9'
AGENT_KID = '001'
AGENT_KID_HEADER_JSON = '{"alg":"HS256","kid":"001","typ":"wazuh-enroll+jwt"}'
AGENT_KID_JWT = ('eyJhbGciOiJIUzI1NiIsImtpZCI6IjAwMSIsInR5cCI6IndhenVoLWVucm9sbCtqd3QifQ.'
                 'eyJleHAiOjE3MDAwMDAwNjAsImlhdCI6MTcwMDAwMDAwMCwianRpIjoiQUFFQ0F3UUZCZ2NJQ1FvTERBME9EdyIsIm5iZiI6MTcwMDAw'
                 'MDAwMH0.'
                 'waWOzsJ3GP5kj1tOAEdpWNBzjqbjGPSqE039h8irCKc')

PASSWORD_KEY = bytes.fromhex(PASSWORD_KEY_HEX)
TOKEN_KEY = bytes.fromhex(TOKEN_KEY_HEX)
REENROLL_KEY = bytes.fromhex(REENROLL_KEY_HEX)


# ---------------------------------------------------------------- key derivation

def test_the_three_derivations_match_their_frozen_known_answers():
    """One password, one token secret and one reenroll_secret, three unrelated keys."""
    assert derive_password_key(PASSWORD).hex() == PASSWORD_KEY_HEX
    assert derive_token_key(bytes.fromhex(TOKEN_SECRET_HEX)).hex() == TOKEN_KEY_HEX
    assert derive_reenroll_key(bytes.fromhex(REENROLL_SECRET_HEX)).hex() == REENROLL_KEY_HEX


def test_the_labels_separate_the_domains():
    """The same 32 bytes under the reenroll label and as a password give unrelated keys.

    This is the property the whole three-credential scheme rests on: a leaked credential of one
    kind cannot be replayed as another.
    """
    material = bytes.fromhex(REENROLL_SECRET_HEX)
    assert derive_reenroll_key(material) != derive_password_key(material.decode('latin-1'))


def test_a_reenroll_secret_may_be_passed_as_hex_or_as_bytes():
    assert derive_reenroll_key(REENROLL_SECRET_HEX) == derive_reenroll_key(bytes.fromhex(REENROLL_SECRET_HEX))


@pytest.mark.parametrize('secret', [b'', bytes(16), bytes(31), bytes(33), 'ff' * 31, 'zz' * 32],
                         ids=['empty', 'sixteen', 'one-short', 'one-long', 'short-hex', 'not-hex'])
def test_a_reenroll_secret_of_the_wrong_size_is_refused(secret):
    with pytest.raises(ValueError):
        derive_reenroll_key(secret)


def test_a_minted_reenroll_secret_is_the_wire_form():
    secret = random_reenroll_secret()
    assert len(secret) == 64 and bytes.fromhex(secret)
    assert random_reenroll_secret() != secret


# ---------------------------------------------------------------- kid shapes

@pytest.mark.parametrize('kid, kind', [
    (TOKEN_KID, KidKind.TOKEN),
    ('AAAAAAAAAAAAAAAAAAAAAA', KidKind.TOKEN),   # 22 chars of zero bytes
    ('001', KidKind.AGENT),
    ('000', KidKind.AGENT),
    ('4294967295', KidKind.AGENT),               # the widest value a uint32 holds
    ('1', KidKind.NONE),                         # not padded to three
    ('0001', KidKind.NONE),                      # padded past three: a non-canonical "001"
    ('4294967296', KidKind.NONE),                # ten digits, but over the uint32 ceiling
    ('12345678901', KidKind.NONE),               # eleven digits
    ('', KidKind.NONE),
    ('AAECAwQFBgcICQoLDA0OD', KidKind.NONE),     # 21 chars: not 16 bytes
    ('AAECAwQFBgcICQoLDA0ODw=', KidKind.NONE),   # padded
    ('AAECAwQFBgcICQoLDA0ODx', KidKind.NONE),    # 22 chars, non-zero trailing bits
    ('not a kid', KidKind.NONE),
])
def test_a_kid_is_classified_by_its_shape_alone(kid, kind):
    assert classify_kid(kid) is kind


def test_the_two_keyed_shapes_cannot_collide():
    """22 base64url characters can never be a canonical agent id, which is at most 10 digits."""
    assert not is_canonical_agent_id(TOKEN_KID)
    assert not is_canonical_b64url_of(AGENT_KID, 16)


@pytest.mark.parametrize('given, expected', [(1, '001'), ('1', '001'), ('0001', '001'), ('001', '001'),
                                             (0, '000'), (1234, '1234'), ('4294967295', '4294967295')])
def test_an_agent_id_is_rendered_canonically(given, expected):
    assert canonical_agent_id(given) == expected
    assert is_canonical_agent_id(expected)


@pytest.mark.parametrize('given', ['', 'abc', '00a', '12345678901', '4294967296', '-1'])
def test_something_that_is_not_an_agent_id_is_refused(given):
    with pytest.raises(ValueError):
        canonical_agent_id(given)


# ---------------------------------------------------------------- signing

def test_the_serialization_is_byte_for_byte_the_frozen_one():
    """The signature is over these exact bytes, so member order and spacing are part of the wire."""
    assert header_json() == HEADER_JSON
    assert header_json(AGENT_KID) == AGENT_KID_HEADER_JSON
    assert header_json(TOKEN_KID) == TOKEN_KID_HEADER_JSON
    assert payload_json(IAT, JTI) == PAYLOAD_JSON


@pytest.mark.parametrize('key, kid, expected, size', [
    (PASSWORD_KEY, None, TOKEN, 210),
    (TOKEN_KEY, TOKEN_KID, TOKEN_KID_JWT, 251),
    (REENROLL_KEY, AGENT_KID, AGENT_KID_JWT, 226),
], ids=['password', 'enrollment-token', 're-enrollment'])
def test_each_credential_kind_reproduces_its_frozen_bearer(key, kid, expected, size):
    token = sign(key, IAT, kid=kid, jti=JTI)
    assert token == expected
    assert len(token) == size


def test_fresh_bearers_verify_and_carry_distinct_jtis():
    minted = {sign(PASSWORD_KEY, NOW) for _ in range(50)}
    assert len(minted) == 50
    for token in minted:
        assert verify(token, PASSWORD_KEY, NOW) is VerifyError.NONE


def test_a_minted_jti_is_the_canonical_form():
    assert is_canonical_b64url_of(random_jti(), JTI_BYTES)


@pytest.mark.parametrize('key, kid, jti', [
    (bytes(16), None, JTI),                       # key of the wrong size
    (PASSWORD_KEY, '1', JTI),                     # kid of neither shape
    (PASSWORD_KEY, None, 'short'),                # jti too short
    (PASSWORD_KEY, None, 'AAECAwQFBgcICQoLDA0OD='),  # jti padded
], ids=['short-key', 'bad-kid', 'short-jti', 'padded-jti'])
def test_the_signer_refuses_to_mint_what_nobody_could_verify(key, kid, jti):
    with pytest.raises(ValueError):
        sign(key, NOW, kid=kid, jti=jti)


# ---------------------------------------------------------------- peeking

@pytest.mark.parametrize('token, expected', [
    (TOKEN, PeekedKid(KidKind.NONE, '')),
    (TOKEN_KID_JWT, PeekedKid(KidKind.TOKEN, TOKEN_KID)),
    (AGENT_KID_JWT, PeekedKid(KidKind.AGENT, AGENT_KID)),
], ids=['password', 'enrollment-token', 're-enrollment'])
def test_the_header_alone_says_which_key_to_resolve(token, expected):
    assert peek_kid(token) == expected


def test_peeking_a_wrong_signature_still_classifies_it():
    """Classification precedes verification: the key has to be resolved before it can be used."""
    assert peek_kid(WRONG_PASSWORD_TOKEN) == PeekedKid(KidKind.NONE, '')


@pytest.mark.parametrize('token', [
    '', 'not.a.token', TOKEN.replace('.', '', 1), TOKEN + '.x',
    b64url_encode(b'{"alg":"HS256","typ":"wazuh-agent+jwt"}') + TOKEN[TOKEN.find('.'):],
    b64url_encode(b'{"alg":"none","typ":"wazuh-enroll+jwt"}') + TOKEN[TOKEN.find('.'):],
    b64url_encode(b'{"alg":"HS256","kid":"1","typ":"wazuh-enroll+jwt"}') + TOKEN[TOKEN.find('.'):],
    b64url_encode(b'{"alg":"HS256","typ":"wazuh-enroll+jwt","x":1}') + TOKEN[TOKEN.find('.'):],
], ids=['empty', 'garbage', 'two-segments', 'four-segments', 'agent-typ', 'alg-none', 'bad-kid', 'extra-member'])
def test_something_that_is_not_this_profile_peeks_as_nothing(token):
    """None, not KidKind.NONE: a hostile peer must not be able to probe the key store with garbage."""
    assert peek_kid(token) is None


# ---------------------------------------------------------------- verification

@pytest.mark.parametrize('token, key, kid', [
    (TOKEN, PASSWORD_KEY, None),
    (TOKEN_KID_JWT, TOKEN_KEY, TOKEN_KID),
    (AGENT_KID_JWT, REENROLL_KEY, AGENT_KID),
], ids=['password', 'enrollment-token', 're-enrollment'])
def test_each_frozen_bearer_verifies_against_its_own_key(token, key, kid):
    assert verify(token, key, NOW, kid=kid) is VerifyError.NONE


def test_the_wrong_password_is_an_invalid_signature_not_a_malformed_token():
    """The distinction is the whole point: the manager sends `invalid_signature`, and the agent
    must NOT re-enroll on it."""
    assert verify(WRONG_PASSWORD_TOKEN, PASSWORD_KEY, NOW) is VerifyError.INVALID_SIGNATURE


def test_a_bearer_is_never_verified_against_a_key_it_did_not_ask_for():
    """Each of these is a correctly signed token presented under the wrong expectation."""
    assert verify(KID_HEADER_TOKEN, PASSWORD_KEY, NOW) is VerifyError.INVALID_TOKEN
    assert verify(TOKEN, PASSWORD_KEY, NOW, kid=AGENT_KID) is VerifyError.INVALID_TOKEN
    assert verify(AGENT_KID_JWT, REENROLL_KEY, NOW, kid='002') is VerifyError.INVALID_TOKEN


def test_a_bearer_signed_with_another_kinds_key_is_an_invalid_signature():
    assert verify(AGENT_KID_JWT, TOKEN_KEY, NOW, kid=AGENT_KID) is VerifyError.INVALID_SIGNATURE


@pytest.mark.parametrize('now, expected', [
    (IAT, VerifyError.NONE),
    (IAT - DEFAULT_CLOCK_SKEW_SEC, VerifyError.NONE),
    (IAT - DEFAULT_CLOCK_SKEW_SEC - 1, VerifyError.STALE_TOKEN),            # issued in the future
    (IAT + LIFETIME_SEC + DEFAULT_CLOCK_SKEW_SEC, VerifyError.NONE),
    (IAT + LIFETIME_SEC + DEFAULT_CLOCK_SKEW_SEC + 1, VerifyError.STALE_TOKEN),  # expired
], ids=['at-iat', 'skew-early', 'too-early', 'skew-late', 'too-late'])
def test_the_accepted_window_is_the_profiles(now, expected):
    assert verify(TOKEN, PASSWORD_KEY, now) is expected


def test_a_widened_skew_admits_a_bearer_the_default_refuses():
    """remoted's jwt_clock_skew knob, which is what a clock-skewed agent recovers through."""
    late = IAT + LIFETIME_SEC + DEFAULT_CLOCK_SKEW_SEC + 60
    assert verify(TOKEN, PASSWORD_KEY, late) is VerifyError.STALE_TOKEN
    assert verify(TOKEN, PASSWORD_KEY, late, skew_sec=600) is VerifyError.NONE


def test_a_key_of_the_wrong_size_fails_closed():
    assert verify(TOKEN, bytes(16), NOW) is VerifyError.INVALID_SIGNATURE


@pytest.mark.parametrize('payload', [
    '{"exp":1700000060,"iat":1700000000,"jti":"AAECAwQFBgcICQoLDA0ODw","nbf":1700000001}',   # nbf != iat
    '{"exp":1700000000,"iat":1700000000,"jti":"AAECAwQFBgcICQoLDA0ODw","nbf":1700000000}',   # exp == iat
    '{"exp":1700000061,"iat":1700000000,"jti":"AAECAwQFBgcICQoLDA0ODw","nbf":1700000000}',   # over the lifetime
    '{"exp":1700000060,"iat":1700000000,"jti":"short","nbf":1700000000}',                    # jti not canonical
    '{"exp":1700000060,"iat":1700000000,"nbf":1700000000}',                                  # jti missing
    '{"exp":1700000060,"iat":1700000000,"jti":"AAECAwQFBgcICQoLDA0ODw","nbf":1700000000,"sub":"001"}',
    '{"exp":1700000060,"iat":"1700000000","jti":"AAECAwQFBgcICQoLDA0ODw","nbf":1700000000}',  # iat a string
    '{"exp":1700000060,"iat":true,"jti":"AAECAwQFBgcICQoLDA0ODw","nbf":1700000000}',          # bool is not an int
], ids=['nbf-drift', 'no-lifetime', 'over-lifetime', 'bad-jti', 'no-jti', 'extra-claim', 'iat-string', 'iat-bool'])
def test_a_structurally_wrong_payload_is_invalid_not_stale(payload):
    """A correctly signed token can still be malformed; saying "stale" would send the agent
    chasing its clock instead of the real fault."""
    import hashlib
    import hmac
    signing_input = f'{b64url_encode(HEADER_JSON.encode())}.{b64url_encode(payload.encode())}'
    mac = hmac.new(PASSWORD_KEY, signing_input.encode(), hashlib.sha256).digest()
    assert verify(f'{signing_input}.{b64url_encode(mac)}', PASSWORD_KEY, NOW) is VerifyError.INVALID_TOKEN


def test_a_repeated_claim_is_refused_rather_than_letting_the_last_one_win():
    import hashlib
    import hmac
    payload = ('{"exp":1700000060,"iat":1700000000,"iat":1700000000,'
               '"jti":"AAECAwQFBgcICQoLDA0ODw","nbf":1700000000}')
    signing_input = f'{b64url_encode(HEADER_JSON.encode())}.{b64url_encode(payload.encode())}'
    mac = hmac.new(PASSWORD_KEY, signing_input.encode(), hashlib.sha256).digest()
    assert verify(f'{signing_input}.{b64url_encode(mac)}', PASSWORD_KEY, NOW) is VerifyError.INVALID_TOKEN


def test_an_oversized_bearer_is_refused_before_any_decoding():
    assert verify('x' * (MAX_TOKEN_BYTES + 1), PASSWORD_KEY, NOW) is VerifyError.INVALID_TOKEN
    assert peek_kid('x' * (MAX_TOKEN_BYTES + 1)) is None
