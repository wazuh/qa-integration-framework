"""
Copyright (C) 2015-2026, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

Unit tests for the enrollment-token codec.

Every expected token below is a frozen vector from the manager's own codec
(wazuh/wazuh: src/unit_tests/shared/test_enrollment_token.c), reproduced here byte for byte. That
is the point of the file: a token minted on this side is one a real agent accepts, and a token
this side refuses is one the manager would refuse too, with the same reason.

Reproduce any vector by hand with:

    python3 -c "import base64,json; print(base64.urlsafe_b64encode(json.dumps(
      {'ver':1,'adr':'siem.example.local','pin':'YJHcNmXtXoM8jZRfk-u_FLNwIMzudzNORJesLvNZCqI'},
      separators=(',',':')).encode()).rstrip(b'=').decode())"

Deviation from tests/unit/test_spki_pin.py's style, deliberately: the tables below are
parametrized rather than looped inside one test, because per-case attribution over an eight-row
normalisation table is worth more than style consistency.

Run with:  PYTHONPATH=src python3 -m pytest tests/unit/test_enrollment_token.py -v
"""
import json

import pytest

from wazuh_testing.utils.enrollment_token import (DEFAULT_PORT, DEFAULT_PREFIX,
                                                  EnrollmentTokenError, TokenError, adr_for,
                                                  adr_to_target, b64url_decode, b64url_encode,
                                                  decode_token, derive_token_key, encode_raw,
                                                  encode_token, normalise_adr, parse_adr)

# The frozen credential: id = 00..0f, secret = 10..1f.
TOKEN_ID = bytes(range(16))
TOKEN_SECRET = bytes(range(0x10, 0x20))
CREDENTIAL = (TOKEN_ID, TOKEN_SECRET)

PIN_HEX = '6091dc3665ed5e833c8d945f93ebbf14b37020ccee77334e4497ac2ef3590aa2'
PIN_B64URL = 'YJHcNmXtXoM8jZRfk-u_FLNwIMzudzNORJesLvNZCqI'
KEY_B64URL = 'AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8'
DERIVED_HEX = '5da72b786a15757caa8d825a74a3474c3f15b048fd1064b49863ffc715a95860'

TOKEN_PIN_ONLY = ('eyJ2ZXIiOjEsImFkciI6InNpZW0uZXhhbXBsZS5sb2NhbCIsInBpbiI6IllKSGNObVh0WG9NOGpaUm'
                  'ZrLXVfRkxOd0lNenVkek5PUkplc0x2TlpDcUkifQ')
TOKEN_WITH_KEY = ('eyJ2ZXIiOjEsImFkciI6InNpZW0uZXhhbXBsZS5sb2NhbCIsInBpbiI6IllKSGNObVh0WG9NOGpaUm'
                  'ZrLXVfRkxOd0lNenVkek5PUkplc0x2TlpDcUkiLCJrZXkiOiJBQUVDQXdRRkJnY0lDUW9MREEwT0R4'
                  'QVJFaE1VRlJZWEdCa2FHeHdkSGg4In0')
TOKEN_PORT_PREFIX = ('eyJ2ZXIiOjEsImFkciI6InNpZW0uZXhhbXBsZS5sb2NhbDo4NDQzL3dhenVoLyIsInBpbiI6Ill'
                     'KSGNObVh0WG9NOGpaUmZrLXVfRkxOd0lNenVkek5PUkplc0x2TlpDcUkifQ')

# The three tokens hardcoded in the installer's own shell harness
# (wazuh/wazuh: src/init/tests/test_enrollment_token.sh). None is a valid token.
INSTALLER_TOKENS = {
    # {"ver":1,"adr":"manager.example.com","pin":"<64 a's>","key":"k1"} -- a hex-shaped pin.
    'pin_is_64_hex_chars': (
        'eyJ2ZXIiOjEsImFkciI6Im1hbmFnZXIuZXhhbXBsZS5jb20iLCJwaW4iOiJhYWFhYWFhYWFhYWFhYWFhYWFhYWFh'
        'YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhIiwia2V5IjoiazEifQ',
        TokenError.BAD_PIN),
    # {"ver":2,"adr":"manager.example.com","ca":"<64 b's>"}
    'version_is_two': (
        'eyJ2ZXIiOjIsImFkciI6Im1hbmFnZXIuZXhhbXBsZS5jb20iLCJjYSI6ImJiYmJiYmJiYmJiYmJiYmJiYmJiYmJi'
        'YmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmJiYmIifQ',
        TokenError.VERSION),
}


# ---------------------------------------------------------------------------------------------
# The frozen vectors
# ---------------------------------------------------------------------------------------------

@pytest.mark.parametrize('adr,kwargs,expected,length', [
    ('siem.example.local', {'pin': PIN_B64URL}, TOKEN_PIN_ONLY, 118),
    ('siem.example.local', {'pin': PIN_B64URL, 'credential': CREDENTIAL}, TOKEN_WITH_KEY, 187),
    ('siem.example.local:8443/wazuh/', {'pin': PIN_B64URL}, TOKEN_PORT_PREFIX, 134),
], ids=['pin_only', 'pin_and_key', 'port_and_prefix'])
def test_encoding_reproduces_the_managers_frozen_vectors(adr, kwargs, expected, length):
    token = encode_token(adr, **kwargs)

    assert token == expected
    assert len(token) == length


def test_a_raw_pin_and_its_base64url_spelling_encode_identically():
    assert encode_token('siem.example.local', pin=bytes.fromhex(PIN_HEX)) == TOKEN_PIN_ONLY


def test_the_envelope_is_compact_json_with_the_mandated_member_order():
    """Whitespace and member order are part of the format, not cosmetic: the manager's
    cJSON_PrintUnformatted emits neither spaces nor a different order."""
    text = b64url_decode(TOKEN_WITH_KEY).decode()

    assert text == ('{"ver":1,"adr":"siem.example.local","pin":"' + PIN_B64URL + '",'
                    '"key":"' + KEY_B64URL + '"}')
    assert ' ' not in text.replace('siem.example.local', '')
    # "ver":1 is a bare integer, not 1.0 and not "1".
    assert '"ver":1,' in text
    assert [text.index(f'"{name}"') for name in ('ver', 'adr', 'pin', 'key')] == \
        sorted(text.index(f'"{name}"') for name in ('ver', 'adr', 'pin', 'key'))


def test_decoding_a_frozen_vector_recovers_every_field():
    token = decode_token(TOKEN_WITH_KEY)

    assert token.ver == 1
    assert token.adr == 'siem.example.local'
    assert token.pin == PIN_B64URL
    assert token.pin_bytes == bytes.fromhex(PIN_HEX)
    assert token.ca is None
    assert (token.key_id, token.key_secret) == CREDENTIAL


# ---------------------------------------------------------------------------------------------
# adr
# ---------------------------------------------------------------------------------------------

@pytest.mark.parametrize('written,canonical', [
    ('h:1517/wazuh-manager', 'h'),
    ('h:1517/wazuh-manager/', 'h'),
    ('h:1517', 'h'),
    ('h/wazuh-manager', 'h'),
    # NOT 'h': the explicitly-empty prefix means no prefix, where a bare host means the default.
    ('h/', 'h/'),
    ('h:8443', 'h:8443'),
    ('h:8443/wazuh/', 'h:8443/wazuh/'),
    ('[2001:db8::1]:1517', '[2001:db8::1]'),
])
def test_adr_normalisation_drops_only_the_defaults(written, canonical):
    assert normalise_adr(written) == canonical


@pytest.mark.parametrize('adr', [
    'siem.example.local', 'manager', '192.0.2.10', '192.0.2.10:8443',
    '[2001:db8::1]', '[2001:db8::1]:8443', '[fe80::1%25eth0]',
    'h/a/b', 'h/a.b~c-d_e',
])
def test_the_adr_grammar_accepts_valid_addresses(adr):
    assert parse_adr(adr).host


@pytest.mark.parametrize('adr', [
    'https://h',        # No scheme is allowed.
    'h:0',              # Port range is 1..65535.
    'h:65536',
    'h:abc',
    'h:',
    '::1',              # An IPv6 literal must be bracketed.
    '[2001:db8::1',     # Unterminated.
    '[fe80::1%eth0]',   # A zone identifier must be percent-encoded as %25.
    'h/bad prefix',
    'h/bad?prefix',
    '',
])
def test_the_adr_grammar_rejects_malformed_addresses(adr):
    with pytest.raises(EnrollmentTokenError) as error:
        parse_adr(adr)
    assert error.value.reason is TokenError.BAD_ADR


def test_adr_for_writes_an_empty_prefix_as_the_explicitly_empty_form():
    """The likeliest way to hand an agent a token that 404s: a bare host means the DEFAULT
    prefix (wazuh-manager), so a bare-root manager can only be written 'host/'."""
    assert adr_for('h', DEFAULT_PORT, '') == 'h/'
    assert adr_for('h', DEFAULT_PORT, DEFAULT_PREFIX) == 'h'
    assert adr_for('h', 8443, 'wazuh') == 'h:8443/wazuh'
    # IPv6 hosts are bracketed for the caller.
    assert adr_for('::1') == '[::1]'


@pytest.mark.parametrize('adr,target', [
    ('h', ('h', DEFAULT_PORT, DEFAULT_PREFIX)),
    ('h/', ('h', DEFAULT_PORT, '')),
    ('h:8443/wazuh/', ('h', 8443, 'wazuh')),
    ('[2001:db8::1]', ('2001:db8::1', DEFAULT_PORT, DEFAULT_PREFIX)),
])
def test_adr_to_target_restores_the_defaults_the_encoding_dropped(adr, target):
    assert adr_to_target(adr) == target


def test_adr_is_kept_verbatim_when_decoding():
    """Normalisation is an encoding step only, so a redundant ':1517' survives a decode."""
    assert decode_token(encode_raw({'ver': 1, 'adr': 'h:1517', 'pin': PIN_B64URL})).adr == 'h:1517'


# ---------------------------------------------------------------------------------------------
# Anchors, pin and credential
# ---------------------------------------------------------------------------------------------

def test_exactly_one_anchor_is_required_when_encoding():
    with pytest.raises(EnrollmentTokenError) as error:
        encode_token('h')
    assert error.value.reason is TokenError.NO_ANCHOR

    with pytest.raises(EnrollmentTokenError) as error:
        encode_token('h', pin=PIN_B64URL, ca='pem')
    assert error.value.reason is TokenError.BOTH_ANCHORS


@pytest.mark.parametrize('members,reason', [
    ({'ver': 1, 'adr': 'h'}, TokenError.NO_ANCHOR),
    ({'ver': 1, 'adr': 'h', 'pin': PIN_B64URL, 'ca': 'pem'}, TokenError.BOTH_ANCHORS),
])
def test_exactly_one_anchor_is_required_when_decoding(members, reason):
    with pytest.raises(EnrollmentTokenError) as error:
        decode_token(encode_raw(members))
    assert error.value.reason is reason


def test_a_ca_anchored_token_round_trips_the_pem_verbatim():
    pem = '-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n'
    token = decode_token(encode_token('h', ca=pem))

    assert (token.ca, token.pin, token.pin_bytes) == (pem, None, None)


@pytest.mark.parametrize('pin', [
    PIN_B64URL[:-1],                        # 42 characters.
    PIN_B64URL + 'A',                       # 44 characters.
    PIN_B64URL + '=',                       # Padded.
    PIN_B64URL.replace('-', '+'),           # Standard alphabet.
    PIN_B64URL.replace('_', '/'),
    PIN_B64URL[:-1] + 'J',                  # Non-canonical trailing bits.
    'a' * 64,                               # Hex-shaped, as the installer's harness uses.
    '',
])
def test_a_pin_must_be_exactly_thirty_two_canonical_bytes(pin):
    with pytest.raises(EnrollmentTokenError) as error:
        decode_token(encode_raw({'ver': 1, 'adr': 'h', 'pin': pin}))
    assert error.value.reason is TokenError.BAD_PIN


def test_a_credential_must_be_thirty_two_bytes_splitting_into_id_and_secret():
    assert decode_token(TOKEN_WITH_KEY).key_id == TOKEN_ID
    assert decode_token(TOKEN_WITH_KEY).key_secret == TOKEN_SECRET

    with pytest.raises(EnrollmentTokenError) as error:
        decode_token(encode_raw({'ver': 1, 'adr': 'h', 'pin': PIN_B64URL,
                                 'key': b64url_encode(bytes(31))}))
    assert error.value.reason is TokenError.BAD_KEY

    with pytest.raises(EnrollmentTokenError) as error:
        encode_token('h', pin=PIN_B64URL, credential=(bytes(15), TOKEN_SECRET))
    assert error.value.reason is TokenError.BAD_KEY


# ---------------------------------------------------------------------------------------------
# Envelope and member-set strictness
# ---------------------------------------------------------------------------------------------

@pytest.mark.parametrize('token', [
    TOKEN_PIN_ONLY + '==',              # Padded.
    TOKEN_PIN_ONLY[:-1] + '+',          # A standard-alphabet character.
    TOKEN_PIN_ONLY[:-1] + '/',
    'A',                                # A length that cannot represent whole bytes.
    'not base64url!',
    '',
])
def test_the_envelope_must_be_canonical_unpadded_base64url(token):
    with pytest.raises(EnrollmentTokenError) as error:
        decode_token(token)
    assert error.value.reason is TokenError.MALFORMED


def test_base64url_decoding_refuses_what_the_stdlib_would_silently_discard():
    """base64.urlsafe_b64decode drops non-alphabet bytes instead of failing, so a corrupted
    token would decode to something plausible."""
    import base64 as stdlib_base64

    corrupted = PIN_B64URL[:10] + '!' + PIN_B64URL[10:]
    assert stdlib_base64.urlsafe_b64decode(corrupted + '===')  # The stdlib is happy.
    with pytest.raises(EnrollmentTokenError):
        b64url_decode(corrupted)


@pytest.mark.parametrize('members', [
    {'ver': 1, 'adr': 'h', 'pin': PIN_B64URL, 'surprise': 'x'},
    {'ver': 1, 'adr': 'h', 'pin': PIN_B64URL, 'ver2': 1},
])
def test_the_member_set_is_closed(members):
    with pytest.raises(EnrollmentTokenError) as error:
        decode_token(encode_raw(members))
    assert error.value.reason is TokenError.MALFORMED


def test_a_duplicate_member_is_refused_rather_than_last_one_winning():
    """Python's json keeps the last duplicate silently, so this guards the object_pairs_hook: a
    token carrying two pins must not quietly resolve to one of them."""
    raw = ('{"ver":1,"adr":"h","pin":"' + PIN_B64URL + '","pin":"' + 'A' * 43 + '"}')

    with pytest.raises(EnrollmentTokenError) as error:
        decode_token(b64url_encode(raw.encode()))
    assert error.value.reason is TokenError.MALFORMED


@pytest.mark.parametrize('members', [
    {'ver': '1', 'adr': 'h', 'pin': PIN_B64URL},
    {'ver': True, 'adr': 'h', 'pin': PIN_B64URL},
    {'ver': 1, 'adr': 1517, 'pin': PIN_B64URL},
    {'ver': 1, 'adr': 'h', 'pin': ['x']},
])
def test_a_member_of_the_wrong_type_is_malformed(members):
    with pytest.raises(EnrollmentTokenError) as error:
        decode_token(encode_raw(members))
    assert error.value.reason is TokenError.MALFORMED


def test_a_body_that_is_not_a_json_object_is_malformed():
    for raw in (b'[]', b'"text"', b'1', b'{'):
        with pytest.raises(EnrollmentTokenError) as error:
            decode_token(b64url_encode(raw))
        assert error.value.reason is TokenError.MALFORMED


@pytest.mark.parametrize('version', [0, 2, -1, 1.5])
def test_only_version_one_is_accepted(version):
    with pytest.raises(EnrollmentTokenError) as error:
        decode_token(encode_raw({'ver': version, 'adr': 'h', 'pin': PIN_B64URL}))
    assert error.value.reason is TokenError.VERSION


def test_a_missing_version_is_a_version_failure_not_a_missing_member_one():
    with pytest.raises(EnrollmentTokenError) as error:
        decode_token(encode_raw({'adr': 'h', 'pin': PIN_B64URL}))
    assert error.value.reason is TokenError.VERSION


def test_encode_raw_performs_no_validation_at_all():
    """It exists only to mint deliberately-invalid fixtures, which a strict encoder cannot."""
    token = encode_raw({'ver': 9, 'adr': '', 'pin': 'nope', 'ca': 'both', 'junk': None})

    assert json.loads(b64url_decode(token).decode())['ver'] == 9
    with pytest.raises(EnrollmentTokenError):
        decode_token(token)


@pytest.mark.parametrize('name', list(INSTALLER_TOKENS))
def test_the_installers_own_sample_tokens_are_refused(name):
    """Recorded, not fixed. The installer's shell decoder accepts non-canonical base64url and
    never checks the pin's length, so its harness uses tokens no agent would accept -- a
    64-character hex-shaped pin, and version 2. The agent's pin comparison rejects both, which is
    the right outcome reported at the wrong layer; tightening the shell side is separate work."""
    token, reason = INSTALLER_TOKENS[name]

    with pytest.raises(EnrollmentTokenError) as error:
        decode_token(token)
    assert error.value.reason is reason


# ---------------------------------------------------------------------------------------------
# Credential derivation
# ---------------------------------------------------------------------------------------------

def test_derive_token_key_matches_the_frozen_known_answer():
    """HKDF-SHA256(IKM=secret, salt=32 zero bytes, info="WAZUH-ENROLL-TOKEN-KEY"+0x01, L=32).
    Note the info label carries no NUL between the text and the version byte."""
    assert derive_token_key(TOKEN_SECRET).hex() == DERIVED_HEX


@pytest.mark.parametrize('secret', [b'', bytes(15), bytes(17), bytes(32)])
def test_derive_token_key_requires_a_sixteen_byte_secret(secret):
    with pytest.raises(EnrollmentTokenError) as error:
        derive_token_key(secret)
    assert error.value.reason is TokenError.BAD_KEY
