"""
Copyright (C) 2015-2026, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

Codec for the agent enrollment token.

The token is what an operator hands to a new agent so it can bootstrap trust in a manager it has
never spoken to: an address to reach, an anchor to check the manager's certificate against, and
optionally a credential to enroll with. On the wire it is a compact JSON object wrapped in
unpadded base64url::

    {"ver":1,"adr":"siem.example.local","pin":"YJHcNmXtXoM8jZRfk-u_FLNwIMzudzNORJesLvNZCqI"}

Members are written in the order ``ver``, ``adr``, ``pin`` or ``ca``, ``key``; ``ver`` is the bare
integer 1; and exactly one anchor is carried -- ``pin`` (the SPKI pin, 43 base64url characters) or
``ca`` (the certificate itself). Neither leaves nothing to verify the manager against, and both
leaves it ambiguous which one wins, so both are rejected rather than one silently taking priority.

This mirrors the manager's own codec (wazuh/wazuh: src/shared/src/enrollment_token.c,
``w_etoken_encode`` / ``w_etoken_decode``) closely enough to mint tokens a real agent accepts and
to reject the ones it would reject; the vectors it is held to are that codec's own, reproduced
byte for byte.

Strictness is deliberate and is not symmetric with every Wazuh component: the installer's shell
decoder (register_configure_agent.sh, ``wet_b64url_decode``) accepts non-canonical base64url
trailing bits and never checks the pin's length, while the agent's C++ pin comparison
(``spkiPinCompare``) rejects both. This module sides with the agent -- the layer that has to fail
closed -- so a token accepted here is one the agent will also accept. :func:`encode_raw` is the
way to mint the invalid tokens that asymmetry needs to be tested with.
"""
import base64
import json
import re
from enum import Enum
from typing import Any, Mapping, NamedTuple, Optional, Tuple, Union

from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

TOKEN_VERSION = 1

# Defaults the `adr` field omits when a token is encoded, so a token for a stock manager carries
# just its host. Mirrors W_ETOKEN_DEFAULT_PORT / W_ETOKEN_DEFAULT_PREFIX.
DEFAULT_PORT = 1517
DEFAULT_PREFIX = 'wazuh-manager'

# Field sizes, mirroring the W_ETOKEN_*_BYTES macros.
PIN_BYTES = 32
ID_BYTES = 16
SECRET_BYTES = 16
KEY_BYTES = ID_BYTES + SECRET_BYTES

# HKDF that turns a token's credential secret into the HS256 key of a `wazuh-enroll+jwt`.
# The info label is 22 bytes plus the version byte, with no NUL between them.
HKDF_SALT = bytes(32)
HKDF_INFO = b'WAZUH-ENROLL-TOKEN-KEY' + b'\x01'
DERIVED_KEY_LENGTH = 32

# The member set is closed: anything else is malformed, not ignored.
_ALLOWED_MEMBERS = ('ver', 'adr', 'pin', 'ca', 'key')
_STRING_MEMBERS = ('adr', 'pin', 'ca', 'key')

_B64URL_ALPHABET = re.compile(r'^[A-Za-z0-9_-]+$')
# host[:port][/[prefix]] -- no scheme. A DNS name, an IPv4 dotted quad, or an IPv6 literal in
# square brackets whose zone identifier is percent-encoded as "%25".
_DNS_HOST = re.compile(r'^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*$')
_IPV6_HOST = re.compile(r'^\[[0-9A-Fa-f:.]+(%25[A-Za-z0-9._~-]+)?\]$')
_PREFIX_SEGMENT = re.compile(r'^[A-Za-z0-9._~-]+$')


class TokenError(str, Enum):
    """Why a token was rejected. One member per ``w_etoken_error_t`` value, same names."""

    MALFORMED = 'malformed'
    VERSION = 'version'
    NO_ANCHOR = 'no_anchor'
    BOTH_ANCHORS = 'both_anchors'
    BAD_ADR = 'bad_adr'
    BAD_PIN = 'bad_pin'
    BAD_KEY = 'bad_key'


class EnrollmentTokenError(ValueError):
    """A token (or a request to build one) that the format does not allow.

    Attributes:
        reason (TokenError): Which rejection this is, so a test can assert on the class of
            failure rather than on a message.
    """

    def __init__(self, reason: TokenError, detail: str = '') -> None:
        self.reason = reason
        super().__init__(f'{reason.value}: {detail}' if detail else reason.value)


class Adr(NamedTuple):
    """A parsed ``adr``. ``port`` and ``prefix`` are None when the field omitted them.

    ``prefix`` is ``''`` -- not None -- for the explicitly-empty form ``host/``, which is how a
    bare-root manager is expressed. A None prefix means "the default", which is not the same
    thing at all.
    """

    host: str
    port: Optional[int]
    prefix: Optional[str]


class EnrollmentToken(NamedTuple):
    """A decoded token. Exactly one of ``pin``/``ca`` is set; ``key`` members are optional."""

    ver: int
    adr: str
    pin: Optional[str]
    pin_bytes: Optional[bytes]
    ca: Optional[str]
    key_id: Optional[bytes]
    key_secret: Optional[bytes]


def b64url_encode(data: bytes) -> str:
    """Encode bytes as unpadded base64url (RFC 4648 section 5)."""
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def b64url_decode(text: str) -> bytes:
    """Decode unpadded base64url, strictly.

    ``base64.urlsafe_b64decode`` calls ``b64decode(validate=False)``, which silently *discards*
    bytes outside the alphabet -- so a token with a stray character in it would decode to
    something plausible instead of being refused. Three checks it does not make are made here:
    the alphabet, a length that can represent whole bytes, and canonical trailing bits (a final
    character whose unused low bits are not zero, RFC 7515 section 2 / RFC 8725 section 3.12).
    The last is the one the installer's shell decoder also omits.

    Raises:
        EnrollmentTokenError: MALFORMED, for any of those.
    """
    if not text or not _B64URL_ALPHABET.match(text):
        raise EnrollmentTokenError(TokenError.MALFORMED, 'not unpadded base64url')
    if len(text) % 4 == 1:
        raise EnrollmentTokenError(TokenError.MALFORMED, 'length cannot represent whole bytes')

    decoded = base64.urlsafe_b64decode(text + '=' * (-len(text) % 4))
    # Canonical form is the only accepted spelling of a given byte string.
    if b64url_encode(decoded) != text:
        raise EnrollmentTokenError(TokenError.MALFORMED, 'non-canonical trailing bits')

    return decoded


def parse_adr(adr: str) -> Adr:
    """Split and validate an ``adr`` against the ``host[:port][/[prefix]]`` grammar.

    Raises:
        EnrollmentTokenError: BAD_ADR.
    """
    if not isinstance(adr, str) or not adr:
        raise EnrollmentTokenError(TokenError.BAD_ADR, 'empty')

    rest, prefix = (adr.split('/', 1) + [None])[:2] if '/' in adr else (adr, None)

    if rest.startswith('['):
        closing = rest.find(']')
        if closing < 0:
            raise EnrollmentTokenError(TokenError.BAD_ADR, 'unterminated IPv6 literal')
        host, after = rest[:closing + 1], rest[closing + 1:]
        if not _IPV6_HOST.match(host):
            raise EnrollmentTokenError(TokenError.BAD_ADR, f'bad IPv6 literal {host!r}')
        port_text = after[1:] if after.startswith(':') else ('' if not after else None)
        if port_text is None:
            raise EnrollmentTokenError(TokenError.BAD_ADR, 'trailing junk after IPv6 literal')
    else:
        host, _, port_text = rest.partition(':')
        # A bare ':' with nothing after it is not "no port", it is a malformed one.
        if ':' in rest and not port_text:
            raise EnrollmentTokenError(TokenError.BAD_ADR, 'empty port')
        if not _DNS_HOST.match(host):
            raise EnrollmentTokenError(TokenError.BAD_ADR, f'bad host {host!r}')

    port = None
    if port_text:
        if not port_text.isdigit():
            raise EnrollmentTokenError(TokenError.BAD_ADR, f'bad port {port_text!r}')
        port = int(port_text)
        if not 1 <= port <= 65535:
            raise EnrollmentTokenError(TokenError.BAD_ADR, f'port {port} out of range')

    if prefix:
        for segment in prefix.rstrip('/').split('/'):
            if not _PREFIX_SEGMENT.match(segment):
                raise EnrollmentTokenError(TokenError.BAD_ADR, f'bad prefix segment {segment!r}')

    return Adr(host=host, port=port, prefix=prefix)


def normalise_adr(adr: str) -> str:
    """Rewrite an ``adr`` in the canonical form an encoded token carries.

    The default port and the default prefix are dropped; an explicitly-empty prefix (``host/``,
    meaning no prefix at all) is kept, because dropping it would turn it into the default.

    Raises:
        EnrollmentTokenError: BAD_ADR.
    """
    parsed = parse_adr(adr)
    text = parsed.host

    if parsed.port is not None and parsed.port != DEFAULT_PORT:
        text += f':{parsed.port}'

    if parsed.prefix is not None and parsed.prefix.rstrip('/') != DEFAULT_PREFIX:
        text += f'/{parsed.prefix}'

    return text


def adr_for(host: str, port: int = DEFAULT_PORT, prefix: str = DEFAULT_PREFIX) -> str:
    """Build a canonical ``adr`` for a manager reachable at ``host``/``port``/``prefix``.

    Note what ``prefix=''`` means: it renders as ``host/``, the explicitly-empty prefix, because a
    bare ``host`` would be read as *the default* prefix (``wazuh-manager``) rather than as none.
    Getting this backwards is the most likely way to hand an agent a token that 404s.

    Args:
        host (str): DNS name, IPv4 dotted quad, or IPv6 literal (bracketed automatically).
        port (int): Listener port. Defaults: 1517, which is then omitted.
        prefix (str): URL prefix, without slashes. Defaults: 'wazuh-manager', then omitted.
            Pass '' for a manager serving at bare root.

    Returns:
        str: The canonical ``adr``.
    """
    if ':' in host and not host.startswith('['):
        host = f'[{host}]'

    return normalise_adr(f'{host}:{port}/{prefix}')


def adr_to_target(adr: str) -> Tuple[str, int, str]:
    """Resolve an ``adr`` into the (host, port, prefix) a client should actually use.

    The inverse of :func:`adr_for`: omitted members come back as the defaults they stand for, and
    the host is unbracketed so it can be handed straight to a socket call.

    Returns:
        Tuple[str, int, str]: (host, port, prefix). The prefix has no surrounding slashes and is
        ``''`` for a bare-root manager.
    """
    parsed = parse_adr(adr)
    host = parsed.host[1:-1] if parsed.host.startswith('[') else parsed.host
    prefix = DEFAULT_PREFIX if parsed.prefix is None else parsed.prefix.strip('/')

    return host, parsed.port if parsed.port is not None else DEFAULT_PORT, prefix


def encode_token(adr: str, *, pin: Union[str, bytes, None] = None, ca: Optional[str] = None,
                 credential: Optional[Tuple[bytes, bytes]] = None) -> str:
    """Encode a valid token.

    There is no ``ver`` parameter: the format has exactly one version and the encoder always
    writes it, exactly as ``w_etoken_encode`` refuses anything else.

    Args:
        adr (str): Address, normalised on the way out. Build it with :func:`adr_for`.
        pin (str | bytes, optional): The SPKI pin -- 43 base64url characters or 32 raw bytes.
        ca (str, optional): A certificate PEM, as the anchor instead of a pin.
        credential (Tuple[bytes, bytes], optional): (id, secret), 16 bytes each.

    Returns:
        str: The token.

    Raises:
        EnrollmentTokenError: NO_ANCHOR or BOTH_ANCHORS when not exactly one of pin/ca is given,
            BAD_PIN for a pin that is not 32 bytes, BAD_KEY for a malformed credential, BAD_ADR
            for an address outside the grammar.
    """
    if pin is None and ca is None:
        raise EnrollmentTokenError(TokenError.NO_ANCHOR, 'pass exactly one of pin/ca')
    if pin is not None and ca is not None:
        raise EnrollmentTokenError(TokenError.BOTH_ANCHORS, 'pass exactly one of pin/ca')

    members: dict = {'ver': TOKEN_VERSION, 'adr': normalise_adr(adr)}

    if pin is not None:
        if isinstance(pin, str):
            if len(b64url_decode(pin)) != PIN_BYTES:
                raise EnrollmentTokenError(TokenError.BAD_PIN,
                                           f'pin must decode to {PIN_BYTES} bytes')
            members['pin'] = pin
        else:
            if len(pin) != PIN_BYTES:
                raise EnrollmentTokenError(TokenError.BAD_PIN,
                                           f'pin must be {PIN_BYTES} bytes, got {len(pin)}')
            members['pin'] = b64url_encode(pin)
    else:
        members['ca'] = ca

    if credential is not None:
        identifier, secret = credential
        if len(identifier) != ID_BYTES or len(secret) != SECRET_BYTES:
            raise EnrollmentTokenError(
                TokenError.BAD_KEY, f'credential must be ({ID_BYTES}, {SECRET_BYTES}) bytes')
        members['key'] = b64url_encode(bytes(identifier) + bytes(secret))

    return encode_raw(members)


def encode_raw(members: Mapping[str, Any]) -> str:
    """Encode an arbitrary member mapping, with no validation at all.

    This exists to mint tokens that are deliberately invalid -- an unknown member, a duplicate
    one, ``ver`` 2, both anchors, a 64-character hex pin -- which a strict encoder cannot produce
    and which the decoder's negative tests need. Member order is the mapping's own, so a test can
    also produce a correctly-shaped token with its members in the wrong order.

    Args:
        members (Mapping[str, Any]): The JSON object's members, in the order to write them.

    Returns:
        str: base64url of the compact JSON, unpadded.
    """
    # separators without spaces: the manager's cJSON_PrintUnformatted emits no whitespace, and a
    # byte-comparing test would fail on it.
    text = json.dumps(dict(members), separators=(',', ':'), ensure_ascii=False)
    return b64url_encode(text.encode())


def _reject_duplicates(pairs) -> dict:
    """json object hook that refuses a repeated member instead of keeping the last one."""
    seen: dict = {}
    for key, value in pairs:
        if key in seen:
            raise EnrollmentTokenError(TokenError.MALFORMED, f'duplicate member {key!r}')
        seen[key] = value
    return seen


def decode_token(token: str) -> EnrollmentToken:
    """Decode and fully validate a token.

    Checks in the order ``w_etoken_decode`` uses, so the reason a token is refused matches what
    the manager would say: malformed envelope or member set, then version, then the anchor count,
    then the address, then the pin, then the credential.

    ``adr`` comes back exactly as written, not normalised -- normalisation is an encoding step
    only, so a token carrying a redundant ``:1517`` decodes with it intact.

    Args:
        token (str): The token text.

    Returns:
        EnrollmentToken: The decoded token.

    Raises:
        EnrollmentTokenError: With ``reason`` naming the rejection.
    """
    raw = b64url_decode(token)

    try:
        members = json.loads(raw.decode(), object_pairs_hook=_reject_duplicates)
    except EnrollmentTokenError:
        raise
    except Exception as error:
        raise EnrollmentTokenError(TokenError.MALFORMED, f'not JSON ({error})') from error

    if not isinstance(members, dict):
        raise EnrollmentTokenError(TokenError.MALFORMED, 'not a JSON object')

    unknown = set(members) - set(_ALLOWED_MEMBERS)
    if unknown:
        raise EnrollmentTokenError(TokenError.MALFORMED,
                                   f'unknown member(s) {sorted(unknown)}')
    for name in _STRING_MEMBERS:
        if name in members and not isinstance(members[name], str):
            raise EnrollmentTokenError(TokenError.MALFORMED, f'{name} must be a string')
    # bool is an int in Python, so exclude it explicitly rather than accept `"ver": true`.
    if 'ver' in members and (isinstance(members['ver'], bool)
                             or not isinstance(members['ver'], (int, float))):
        raise EnrollmentTokenError(TokenError.MALFORMED, 'ver must be a number')

    # A missing `ver` is a version failure, not a missing-member one.
    if members.get('ver') != TOKEN_VERSION:
        raise EnrollmentTokenError(TokenError.VERSION,
                                   f'unsupported version {members.get("ver")!r}')

    has_pin, has_ca = 'pin' in members, 'ca' in members
    if not has_pin and not has_ca:
        raise EnrollmentTokenError(TokenError.NO_ANCHOR, 'neither pin nor ca')
    if has_pin and has_ca:
        raise EnrollmentTokenError(TokenError.BOTH_ANCHORS, 'both pin and ca')

    if 'adr' not in members:
        raise EnrollmentTokenError(TokenError.BAD_ADR, 'missing')
    parse_adr(members['adr'])

    pin_bytes = None
    if has_pin:
        try:
            pin_bytes = b64url_decode(members['pin'])
        except EnrollmentTokenError as error:
            raise EnrollmentTokenError(TokenError.BAD_PIN, str(error)) from error
        if len(pin_bytes) != PIN_BYTES:
            raise EnrollmentTokenError(TokenError.BAD_PIN,
                                       f'{len(pin_bytes)} bytes, expected {PIN_BYTES}')

    key_id = key_secret = None
    if 'key' in members:
        try:
            material = b64url_decode(members['key'])
        except EnrollmentTokenError as error:
            raise EnrollmentTokenError(TokenError.BAD_KEY, str(error)) from error
        if len(material) != KEY_BYTES:
            raise EnrollmentTokenError(TokenError.BAD_KEY,
                                       f'{len(material)} bytes, expected {KEY_BYTES}')
        key_id, key_secret = material[:ID_BYTES], material[ID_BYTES:]

    return EnrollmentToken(ver=TOKEN_VERSION, adr=members['adr'], pin=members.get('pin'),
                           pin_bytes=pin_bytes, ca=members.get('ca'),
                           key_id=key_id, key_secret=key_secret)


def derive_token_key(secret: bytes) -> bytes:
    """Derive the 32-byte HS256 key a token's credential secret stands for.

    HKDF-SHA256(IKM=secret, salt=32 zero bytes, info="WAZUH-ENROLL-TOKEN-KEY"+0x01, L=32), which
    is ``w_etoken_derive_key``. Provided with its known-answer test and nothing more: no component
    on the manager branch consumes the result yet, so where it belongs on the wire is not settled
    and this module does not guess.

    Args:
        secret (bytes): The token's 16-byte credential secret.

    Returns:
        bytes: The 32-byte derived key.

    Raises:
        EnrollmentTokenError: BAD_KEY when the secret is not 16 bytes.
    """
    if len(secret) != SECRET_BYTES:
        raise EnrollmentTokenError(TokenError.BAD_KEY,
                                   f'secret must be {SECRET_BYTES} bytes, got {len(secret)}')

    return HKDF(algorithm=SHA256(), length=DERIVED_KEY_LENGTH, salt=HKDF_SALT,
                info=HKDF_INFO).derive(bytes(secret))
