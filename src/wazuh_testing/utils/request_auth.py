"""
Copyright (C) 2015-2026, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2

AES-CMAC request-authentication primitives for the HTTPS agent protocol.

The agent signs every request with AES-128 CMAC over a canonical byte sequence and sends the
result in two headers:

    protocol-version: 1
    Authorization: Wazuh <agent-id>:<timestamp>:<mac>

These helpers build that canonical request, compute the MAC, parse the header, and derive the
CMAC key from an agent key string. They mirror the agent implementation (canonicalRequest.cpp,
cmacSigner.cpp, keyProvider.cpp) byte-for-byte, so a MAC signed by the agent verifies here and
vice versa.
"""
from typing import Optional, Tuple

from cryptography.hazmat.primitives import cmac
from cryptography.hazmat.primitives.ciphers import algorithms

# Authentication protocol version (part of the canonical request, so it is authenticated).
PROTOCOL_VERSION = '1'
_AUTH_SCHEME = 'Wazuh '
CMAC_KEY_BYTES = 16  # AES-128.

# Timestamp validation window (seconds): reject requests older than MAX_AGE or more than
# MAX_SKEW seconds in the future.
TIMESTAMP_MAX_AGE = 300
TIMESTAMP_MAX_SKEW = 30


def derive_cmac_key(agent_key: str) -> bytes:
    """Derive the AES-128 CMAC key from an agent key string (32 lowercase hex chars).

    Mirrors the agent's ConfigKeyProvider: the key string is hex-decoded to exactly 16 bytes.

    Args:
        agent_key (str): The agent key as hex (32 characters).

    Returns:
        bytes: The 16-byte AES-128 key.

    Raises:
        ValueError: If the string is not exactly 16 bytes of hexadecimal.
    """
    key = bytes.fromhex(agent_key)
    if len(key) != CMAC_KEY_BYTES:
        raise ValueError(f'CMAC key must be {CMAC_KEY_BYTES} bytes ({CMAC_KEY_BYTES * 2} hex chars)')
    return key


def build_canonical_request(method: str, target: str, agent_id: str,
                            timestamp, body: bytes) -> bytes:
    """Build the exact byte sequence the MAC is computed over.

    Layout (each separator is a single ``0x0A``; there is no trailing newline after the body)::

        WAZUH-REQUEST\\n<protocol-version>\\n<UPPERCASE-METHOD>\\n<request-target>\\n<agent-id>\\n<timestamp>\\n<body>

    Args:
        method (str): HTTP method (upper-cased into the canonical request).
        target (str): Raw request target (path plus query string), exactly as transmitted.
        agent_id (str): The agent identifier.
        timestamp: UNIX timestamp in seconds (int or str).
        body (bytes): Exact request body bytes (may be empty).

    Returns:
        bytes: The canonical request.
    """
    head = (f'WAZUH-REQUEST\n{PROTOCOL_VERSION}\n{method.upper()}\n{target}\n'
            f'{agent_id}\n{timestamp}\n').encode()
    return head + (body or b'')


def compute_cmac(key: bytes, message: bytes) -> str:
    """Return AES-128 CMAC(key, message) encoded as 32 lowercase hexadecimal characters.

    Args:
        key (bytes): The 16-byte AES-128 key.
        message (bytes): The message to authenticate (the canonical request).

    Returns:
        str: The 16-byte MAC as 32 lowercase hex characters.
    """
    context = cmac.CMAC(algorithms.AES(key))
    context.update(message)
    return context.finalize().hex()


def parse_authorization(header: str) -> Optional[Tuple[str, str, str]]:
    """Parse an ``Authorization: Wazuh <id>:<ts>:<mac>`` header value.

    Args:
        header (str): The Authorization header value.

    Returns:
        Optional[Tuple[str, str, str]]: (agent_id, timestamp, mac), or None if the header
            is missing the scheme or is malformed.
    """
    if not header.startswith(_AUTH_SCHEME):
        return None
    parts = header[len(_AUTH_SCHEME):].split(':', 2)
    if len(parts) != 3 or not all(parts):
        return None
    return parts[0], parts[1], parts[2]


def sign_authorization(method: str, target: str, agent_id: str, timestamp, body: bytes,
                       key: bytes) -> str:
    """Build the ``Wazuh <id>:<ts>:<mac>`` Authorization value for a request.

    Convenience for a signing client (a test or driver playing the agent).

    Args:
        method (str): HTTP method.
        target (str): Raw request target.
        agent_id (str): The agent identifier.
        timestamp: UNIX timestamp in seconds.
        body (bytes): Exact request body bytes.
        key (bytes): The 16-byte AES-128 CMAC key.

    Returns:
        str: The Authorization header value.
    """
    canonical = build_canonical_request(method, target, agent_id, timestamp, body)
    mac = compute_cmac(key, canonical)
    return f'{_AUTH_SCHEME}{agent_id}:{timestamp}:{mac}'
