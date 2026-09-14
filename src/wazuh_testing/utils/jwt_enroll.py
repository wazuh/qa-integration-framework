"""
Copyright (C) 2015-2026, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

The ``wazuh-enroll+jwt`` bearer: the credential every ``POST /enroll`` carries.

Up to wazuh/wazuh#38582 an agent authenticated ``/enroll`` with an AES-CMAC ``Authorization:
WazuhEnroll <ts>:<mac>`` header; that scheme left the agent in that issue and this module is what
replaced it here. One profile now carries three different credentials, told apart by the shape of
the header's ``kid`` -- which is the whole trick, and the reason a single verifier can serve all
three without the caller declaring in advance which one it expects::

    no `kid`     the manager's shared enrollment password   HKDF info "WAZUH-ENROLL-JWT-KEY"
    22 b64url    an enrollment token's 16-byte id           HKDF info "WAZUH-ENROLL-TOKEN-KEY"
    "001"        a re-enrolling agent's own canonical id    HKDF info "WAZUH-REENROLL-KEY"

The two keyed shapes are disjoint: 22 canonical base64url characters can never be a canonical
agent id (at most 10 digits) and vice versa, so :func:`classify_kid` needs no hint from the
caller. :func:`peek_kid` is the bounded look that happens *before* any key is resolved, so a
hostile peer cannot probe the key store with garbage.

This mirrors wazuh/wazuh: src/shared_modules/utils/jwt/jwtEnroll*.hpp closely enough to mint
bearers a real manager accepts and to reject the ones it would reject -- the serialization is
byte-for-byte (members in ASCII order, no whitespace), because the signature is over those very
bytes and a re-serializing verifier would accept tokens the manager refuses.

Deliberately *not* provided: a ``jti`` replay store. The manager has none either (the profile
relies on the TLS-authenticated channel, see jwtProfileV1.hpp), so adding one here would make the
simulator stricter than the thing it simulates.

Run the unit tests with:  PYTHONPATH=src python3 -m pytest tests/unit/test_jwt_enroll.py -v
"""
import base64
import hashlib
import hmac
import json
import os
import re
import time
from enum import Enum
from typing import NamedTuple, Optional, Union

from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from wazuh_testing.utils.enrollment_token import derive_token_key

# Profile constants (jwtProfileV1.hpp / jwtEnrollProfileV1.hpp). None of these is a knob.
ALG = 'HS256'
TYP = 'wazuh-enroll+jwt'
KEY_BYTES = 32
HMAC_BYTES = 32
# Every token declares exp = iat + LIFETIME_SEC, and a verifier requires exp - iat <= that.
LIFETIME_SEC = 60
MAX_TOKEN_BYTES = 4096
JTI_BYTES = 16
JTI_CHARS = 22

# The two operator knobs (remoted's jwt_max_age / jwt_clock_skew) at their profile defaults.
# MAX_AGE bounds how old a token may be when the manager sees it; it does not widen LIFETIME_SEC.
DEFAULT_MAX_AGE_SEC = 60
DEFAULT_CLOCK_SKEW_SEC = 30

# HKDF: one salt, one version byte, three domain-separating labels. RFC 5869's "omitted salt is
# HashLen zero bytes" is spelled out rather than relied upon, exactly as the C++ does.
HKDF_SALT = bytes(32)
HKDF_INFO_VERSION = b'\x01'
PASSWORD_HKDF_INFO = b'WAZUH-ENROLL-JWT-KEY' + HKDF_INFO_VERSION
TOKEN_HKDF_INFO = b'WAZUH-ENROLL-TOKEN-KEY' + HKDF_INFO_VERSION
REENROLL_HKDF_INFO = b'WAZUH-REENROLL-KEY' + HKDF_INFO_VERSION

TOKEN_ID_BYTES = 16
TOKEN_SECRET_BYTES = 16
TOKEN_KID_CHARS = 22
# global.db's reenroll_secret: 32 bytes, on the wire as 64 hex characters.
REENROLL_SECRET_BYTES = 32
REENROLL_SECRET_HEX_CHARS = 2 * REENROLL_SECRET_BYTES

# canonicalAgentId.hpp: digits only, at most 10, holding a value a uint32 can, zero-padded to
# exactly 3 wide and no wider ("1" and "0001" are both non-canonical spellings of "001"). The
# strict spelling is what a `kid` must already be -- a token is a protocol message, not user
# input, so no normalisation happens on the way in.
AGENT_ID_MIN_WIDTH = 3
AGENT_ID_MAX_DIGITS = 10
AGENT_ID_MAX_VALUE = 0xFFFFFFFF

_B64URL_ALPHABET = re.compile(r'^[A-Za-z0-9_-]+$')
_DIGITS = re.compile(r'^[0-9]+$')


class KidKind(Enum):
    """Which key a bearer asks for. Mirrors ``JwtEnrollTokenVerifier::KidKind``."""

    NONE = 'none'    #: header {alg, typ}: the shared enrollment-password key
    TOKEN = 'token'  #: `kid` = an enrollment token id
    AGENT = 'agent'  #: `kid` = a canonical agent id (re-enrollment)


class VerifyError(Enum):
    """Why a bearer was refused. One member per ``jwt_profile::v1::VerifyError`` value.

    The three failures are kept apart because the manager maps them onto *different* 401 classes
    (``invalid_signature`` vs ``stale_token``), and the agent's policy then treats those
    differently -- collapsing them here would make the simulator unable to drive that policy.
    """

    NONE = 'none'
    INVALID_TOKEN = 'invalid_token'          #: grammar, base64url, JSON, header/claim set, jti
    INVALID_SIGNATURE = 'invalid_signature'  #: HMAC mismatch, or a key of the wrong size
    STALE_TOKEN = 'stale_token'              #: future iat, expired, or older than the accepted age


class PeekedKid(NamedTuple):
    """What :func:`peek_kid` learned from the header alone. ``text`` is '' for :attr:`KidKind.NONE`."""

    kind: KidKind
    text: str


def b64url_encode(data: bytes) -> str:
    """Encode bytes as unpadded base64url (RFC 4648 section 5)."""
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def b64url_decode_canonical(text: str) -> Optional[bytes]:
    """Decode unpadded base64url, or None if ``text`` is not its canonical spelling.

    Non-throwing on purpose, unlike :func:`wazuh_testing.utils.enrollment_token.b64url_decode`: a
    malformed segment inside a bearer is an ordinary verification outcome, not an exception. The
    canonical check (RFC 7515 section 2) rejects a final character whose unused low bits are set,
    so exactly one spelling of any byte string is accepted.
    """
    if not text or not _B64URL_ALPHABET.match(text) or len(text) % 4 == 1:
        return None
    decoded = base64.urlsafe_b64decode(text + '=' * (-len(text) % 4))
    return decoded if b64url_encode(decoded) == text else None


def is_canonical_b64url_of(text: str, size: int) -> bool:
    """Return True if ``text`` is the canonical base64url of exactly ``size`` bytes."""
    decoded = b64url_decode_canonical(text)
    return decoded is not None and len(decoded) == size


def is_canonical_agent_id(text: str) -> bool:
    """Return True if ``text`` is *already* the canonical spelling of an agent id.

    Not merely "digits, 3 to 10 wide": ``0001`` has the right shape but is the non-canonical
    spelling of ``001``, and the manager's strict parse refuses it. Padding is to exactly three
    and no wider, so the check is the round trip through :func:`canonical_agent_id`.
    """
    if not text or not _DIGITS.match(text) or len(text) > AGENT_ID_MAX_DIGITS:
        return False
    value = int(text)
    return value <= AGENT_ID_MAX_VALUE and str(value).zfill(AGENT_ID_MIN_WIDTH) == text


def canonical_agent_id(agent_id: Union[int, str]) -> str:
    """Render an agent id in its canonical form ('1', 1 and '0001' all become '001').

    Raises:
        ValueError: for anything that is not an agent id at all -- non-digits, more than 10
            digits, or a value a uint32 cannot hold.
    """
    text = str(agent_id).strip()
    if not _DIGITS.match(text) or len(text) > AGENT_ID_MAX_DIGITS or int(text) > AGENT_ID_MAX_VALUE:
        raise ValueError(f'not an agent id: {agent_id!r}')
    return str(int(text)).zfill(AGENT_ID_MIN_WIDTH)


def classify_kid(kid: str) -> KidKind:
    """Classify a ``kid`` by its shape alone -- the two keyed forms cannot collide.

    Returns :attr:`KidKind.NONE` for text that is neither, which callers must treat as "not a
    ``wazuh-enroll+jwt`` at all" rather than as the shared-key form.
    """
    if is_canonical_b64url_of(kid, TOKEN_ID_BYTES):
        return KidKind.TOKEN
    if is_canonical_agent_id(kid):
        return KidKind.AGENT
    return KidKind.NONE


def derive_password_key(password: str) -> bytes:
    """Derive the shared HS256 key from the manager's enrollment password.

    HKDF-SHA256(IKM=password, salt=32 zero bytes, info="WAZUH-ENROLL-JWT-KEY"+0x01, L=32), which is
    ``jwt_profile::v1::enroll::deriveEnrollKey``. The password is taken as its UTF-8 bytes with no
    trailing newline: authd strips the newline when it reads authd.pass, so a password read from a
    file must be stripped by the caller too.
    """
    ikm = password.encode() if isinstance(password, str) else bytes(password)
    return HKDF(algorithm=SHA256(), length=KEY_BYTES, salt=HKDF_SALT, info=PASSWORD_HKDF_INFO).derive(ikm)


def derive_reenroll_key(secret: Union[bytes, str]) -> bytes:
    """Derive an agent's re-enrollment HS256 key from its 32-byte ``reenroll_secret``.

    HKDF-SHA256(IKM=secret, salt=32 zero bytes, info="WAZUH-REENROLL-KEY"+0x01, L=32), which is
    ``w_reenroll_derive_key`` on the agent. The secret may be passed as the 32 raw bytes or as the
    64 hex characters it travels as in the ``/enroll`` response.

    Raises:
        ValueError: if the secret is not 32 bytes (or 64 hex characters).
    """
    if isinstance(secret, str):
        if len(secret) != REENROLL_SECRET_HEX_CHARS:
            raise ValueError(f'reenroll_secret must be {REENROLL_SECRET_HEX_CHARS} hex chars, got {len(secret)}')
        try:
            secret = bytes.fromhex(secret)
        except ValueError as error:
            raise ValueError('reenroll_secret is not hexadecimal') from error
    if len(secret) != REENROLL_SECRET_BYTES:
        raise ValueError(f'reenroll_secret must be {REENROLL_SECRET_BYTES} bytes, got {len(secret)}')

    return HKDF(algorithm=SHA256(), length=KEY_BYTES, salt=HKDF_SALT, info=REENROLL_HKDF_INFO).derive(bytes(secret))


def random_reenroll_secret() -> str:
    """Mint a fresh ``reenroll_secret`` in the form it travels in: 64 hex characters."""
    return os.urandom(REENROLL_SECRET_BYTES).hex()


def random_jti() -> str:
    """Mint a fresh ``jti``: 16 random bytes as 22 canonical base64url characters."""
    return b64url_encode(os.urandom(JTI_BYTES))


def header_json(kid: Optional[str] = None) -> str:
    """The header's exact bytes: members in ASCII order (``alg``, ``kid``, ``typ``), no whitespace."""
    if kid is None:
        return f'{{"alg":"{ALG}","typ":"{TYP}"}}'
    return f'{{"alg":"{ALG}","kid":"{kid}","typ":"{TYP}"}}'


def payload_json(iat: int, jti: str) -> str:
    """The payload's exact bytes: ``exp``, ``iat``, ``jti``, ``nbf``, in that order, no whitespace."""
    return f'{{"exp":{iat + LIFETIME_SEC},"iat":{iat},"jti":"{jti}","nbf":{iat}}}'


def sign(key: bytes, now: Optional[int] = None, kid: Optional[str] = None, jti: Optional[str] = None) -> str:
    """Mint a ``wazuh-enroll+jwt``.

    Args:
        key (bytes): The 32-byte HKDF-derived key, from one of the three ``derive_*`` functions.
        now (int, optional): Wall clock of this attempt; ``iat = nbf = now``, ``exp = now +
            LIFETIME_SEC``. Defaults to the current time. Pass a shifted value to mint the stale
            and future bearers a ``stale_token`` test needs.
        kid (str, optional): The key id, of one of the two shapes :func:`classify_kid` accepts.
            Omit for the shared-password form.
        jti (str, optional): A fixed jti instead of 16 fresh CSPRNG bytes. Tests only.

    Returns:
        str: The compact JWS.

    Raises:
        ValueError: for a key of the wrong size, a ``kid`` of neither shape, or a non-canonical
            ``jti`` override -- each of which the C++ signer returns nullopt for rather than
            emitting a token nobody can verify.
    """
    if len(key) != KEY_BYTES:
        raise ValueError(f'key must be {KEY_BYTES} bytes, got {len(key)}')
    if kid is not None and classify_kid(kid) is KidKind.NONE:
        raise ValueError(f'kid is of neither accepted shape: {kid!r}')
    if jti is None:
        jti = random_jti()
    elif not is_canonical_b64url_of(jti, JTI_BYTES):
        raise ValueError(f'jti must be {JTI_CHARS} canonical base64url chars: {jti!r}')

    iat = int(time.time()) if now is None else int(now)
    signing_input = f'{b64url_encode(header_json(kid).encode())}.{b64url_encode(payload_json(iat, jti).encode())}'
    mac = hmac.new(key, signing_input.encode(), hashlib.sha256).digest()
    return f'{signing_input}.{b64url_encode(mac)}'


def peek_kid(token: str) -> Optional[PeekedKid]:
    """Read the header -- grammar and header only, no signature -- to learn which key to resolve.

    Returns None when the text is not a ``wazuh-enroll+jwt`` at all (bad grammar, wrong
    ``alg``/``typ``, a ``kid`` of neither shape, any extra header member), so nothing peeked is
    trusted and no key lookup happens for garbage. Nothing here is trusted until :func:`verify`
    passes with the key this named.
    """
    parts = _split_compact(token)
    if parts is None:
        return None
    header = _strict_object(b64url_decode_canonical(parts[0]), {'alg': str, 'typ': str})
    if header is not None:
        return PeekedKid(KidKind.NONE, '') if header['alg'] == ALG and header['typ'] == TYP else None

    header = _strict_object(b64url_decode_canonical(parts[0]), {'alg': str, 'kid': str, 'typ': str})
    if header is None or header['alg'] != ALG or header['typ'] != TYP:
        return None
    kind = classify_kid(header['kid'])
    return None if kind is KidKind.NONE else PeekedKid(kind, header['kid'])


def verify(token: str, key: bytes, now: Optional[int] = None, kid: Optional[str] = None,
           max_age_sec: int = DEFAULT_MAX_AGE_SEC, skew_sec: int = DEFAULT_CLOCK_SKEW_SEC) -> VerifyError:
    """Verify a bearer against the key the caller resolved for it.

    The signature is checked before anything in the payload is looked at, and the header must be
    exactly the form ``kid`` implies: a token naming another ``kid`` -- or none -- is
    :attr:`VerifyError.INVALID_TOKEN` before any HMAC, never verified against a key it did not
    ask for.

    Args:
        token (str): The compact JWS.
        key (bytes): The 32-byte key for this token's ``kid``.
        now (int, optional): The verifying clock. Defaults to the current time.
        kid (str, optional): The ``kid`` the caller resolved the key for; None for the
            shared-password form, whose header must carry no ``kid``.
        max_age_sec (int, optional): How old a token may be. Defaults to the profile's 60.
        skew_sec (int, optional): Tolerated clock skew. Defaults to the profile's 30.

    Returns:
        VerifyError: :attr:`VerifyError.NONE` when the token is good.
    """
    parts = _split_compact(token)
    if parts is None:
        return VerifyError.INVALID_TOKEN

    fields = {'alg': str, 'typ': str} if kid is None else {'alg': str, 'kid': str, 'typ': str}
    header = _strict_object(b64url_decode_canonical(parts[0]), fields)
    if header is None or header['alg'] != ALG or header['typ'] != TYP:
        return VerifyError.INVALID_TOKEN
    if kid is not None and (header['kid'] != kid or classify_kid(kid) is KidKind.NONE):
        return VerifyError.INVALID_TOKEN

    if len(key) != KEY_BYTES:
        return VerifyError.INVALID_SIGNATURE
    signature = b64url_decode_canonical(parts[2])
    expected = hmac.new(key, f'{parts[0]}.{parts[1]}'.encode(), hashlib.sha256).digest()
    if signature is None or not hmac.compare_digest(expected, signature):
        return VerifyError.INVALID_SIGNATURE

    claims = _strict_object(b64url_decode_canonical(parts[1]),
                            {'exp': int, 'iat': int, 'jti': str, 'nbf': int})
    if claims is None:
        return VerifyError.INVALID_TOKEN
    error = _check_time_rules(claims['iat'], claims['nbf'], claims['exp'],
                              int(time.time()) if now is None else int(now), max_age_sec, skew_sec)
    if error is not VerifyError.NONE:
        return error
    return VerifyError.NONE if is_canonical_b64url_of(claims['jti'], JTI_BYTES) else VerifyError.INVALID_TOKEN


def _split_compact(token: str):
    """Split the compact grammar, or None: exactly three canonical base64url segments, bounded.

    Mirrors ``splitCompact``, including the size cap being applied before any decoding and the
    signature segment being required to be exactly 32 bytes -- so an oversized or truncated MAC is
    refused as a grammar failure rather than reaching a constant-time comparison.
    """
    if not token or len(token.encode()) > MAX_TOKEN_BYTES:
        return None
    segments = token.split('.')
    if len(segments) != 3:
        return None
    header64, payload64, signature64 = segments
    if not header64 or not payload64:
        return None
    if b64url_decode_canonical(header64) is None or b64url_decode_canonical(payload64) is None:
        return None
    return None if not is_canonical_b64url_of(signature64, HMAC_BYTES) else (header64, payload64, signature64)


def _strict_object(raw: Optional[bytes], fields: dict) -> Optional[dict]:
    """Parse one JSON object whose member set is exactly ``fields``, or None.

    Mirrors ``StrictJsonObject``: the member set is closed (an extra member is a rejection, not
    something to ignore), each member's type is fixed, numbers are non-negative integers, and the
    text is ASCII. ``bool`` is excluded explicitly because it is an ``int`` in Python and
    ``{"iat": true}`` would otherwise parse as 1.
    """
    if raw is None:
        return None
    try:
        text = raw.decode('ascii')
    except UnicodeDecodeError:
        return None
    try:
        parsed = json.loads(text, object_pairs_hook=_reject_duplicates)
    except ValueError:
        return None
    if not isinstance(parsed, dict) or parsed.keys() != fields.keys():
        return None
    for name, expected in fields.items():
        value = parsed[name]
        if expected is int:
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                return None
        elif not isinstance(value, expected):
            return None
    return parsed


def _reject_duplicates(pairs) -> dict:
    """Reject a repeated member rather than letting the last one win."""
    seen = {}
    for name, value in pairs:
        if name in seen:
            raise ValueError(f'duplicate member: {name}')
        seen[name] = value
    return seen


def _check_time_rules(iat: int, nbf: int, exp: int, now: int, max_age_sec: int, skew_sec: int) -> VerifyError:
    """The profile's time rules (``checkTimeRules``): structural first, then clock-relative.

    Structural failures are INVALID_TOKEN, not STALE_TOKEN: a token whose ``nbf`` disagrees with
    its ``iat``, or that claims a lifetime longer than the profile allows, is malformed at any
    clock, and telling an agent its clock is wrong would send it chasing the wrong fix.
    """
    if nbf != iat or exp <= iat or exp - iat > LIFETIME_SEC:
        return VerifyError.INVALID_TOKEN
    if iat > now + skew_sec:
        return VerifyError.STALE_TOKEN       # issued in the future
    if now > exp + skew_sec:
        return VerifyError.STALE_TOKEN       # expired
    if now >= iat and now - iat > max_age_sec + skew_sec:
        return VerifyError.STALE_TOKEN       # older than the accepted age
    return VerifyError.NONE


# Re-exported so a caller needs one import for all three key derivations. The token-secret HKDF
# lives with the token codec (it is that format's own key, with that module's frozen vector); it
# is not reimplemented here, so the two can never drift apart.
__all__ = [
    'ALG', 'TYP', 'KEY_BYTES', 'LIFETIME_SEC', 'MAX_TOKEN_BYTES', 'JTI_BYTES', 'JTI_CHARS',
    'DEFAULT_MAX_AGE_SEC', 'DEFAULT_CLOCK_SKEW_SEC', 'TOKEN_ID_BYTES', 'TOKEN_SECRET_BYTES',
    'TOKEN_KID_CHARS', 'REENROLL_SECRET_BYTES', 'REENROLL_SECRET_HEX_CHARS',
    'KidKind', 'VerifyError', 'PeekedKid',
    'b64url_encode', 'b64url_decode_canonical', 'is_canonical_b64url_of', 'is_canonical_agent_id',
    'canonical_agent_id', 'classify_kid', 'derive_password_key', 'derive_token_key',
    'derive_reenroll_key', 'random_reenroll_secret', 'random_jti', 'header_json', 'payload_json',
    'sign', 'peek_kid', 'verify',
]
