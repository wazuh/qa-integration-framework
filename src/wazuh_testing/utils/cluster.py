# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
from base64 import b64encode
from random import choices, randrange
from string import ascii_lowercase, digits
from struct import pack

from cryptography.fernet import Fernet

CLUSTER_DATA_HEADER_SIZE = 20
CLUSTER_CMD_HEADER_SIZE = 12
CLUSTER_HEADER_FORMAT = '!2I{}s'.format(CLUSTER_CMD_HEADER_SIZE)
FERNET_KEY = ''.join(choices(ascii_lowercase + digits, k=32))
_my_fernet = Fernet(b64encode(FERNET_KEY.encode()))
COUNTER = randrange(100000)


def cluster_msg_build(cmd: bytes = None, counter: int = None, payload: bytes = None, encrypt=True) -> bytes:
    """Build a message using cluster protocol."""
    cmd_len = len(cmd)
    if cmd_len > CLUSTER_CMD_HEADER_SIZE:
        raise Exception("Length of command '{}' exceeds limit ({}/{}).".format(cmd, cmd_len,
                                                                               CLUSTER_CMD_HEADER_SIZE))

    encrypted_data = _my_fernet.encrypt(payload) if encrypt else payload
    out_msg = bytearray(CLUSTER_DATA_HEADER_SIZE + len(encrypted_data))

    # Add - to command until it reaches cmd length
    cmd = cmd + b' ' + b'-' * (CLUSTER_CMD_HEADER_SIZE - cmd_len - 1)

    out_msg[:CLUSTER_DATA_HEADER_SIZE] = pack(CLUSTER_HEADER_FORMAT, counter, len(encrypted_data), cmd)
    out_msg[CLUSTER_DATA_HEADER_SIZE:CLUSTER_DATA_HEADER_SIZE + len(encrypted_data)] = encrypted_data

    return bytes(out_msg[:CLUSTER_DATA_HEADER_SIZE + len(encrypted_data)])
