# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
from base64 import b64encode
from random import choices, randrange
from string import ascii_lowercase, digits
from struct import pack
import re

from cryptography.fernet import Fernet

CLUSTER_DATA_HEADER_SIZE = 20
CLUSTER_CMD_HEADER_SIZE = 12
CLUSTER_HEADER_FORMAT = '!2I{}s'.format(CLUSTER_CMD_HEADER_SIZE)
FERNET_KEY = ''.join(choices(ascii_lowercase + digits, k=32))
_my_fernet = Fernet(b64encode(FERNET_KEY.encode()))
COUNTER = randrange(100000)


def create_authd_request(input):
    """
    Creates a command to request keys to Authd.

    Args:
        input (dict): Dictionary with the content of the request command.
    """
    command = ''

    if 'password' in input:
        password = input['password']
        command = command + f"OSSEC PASS: {password} "

    command = command + 'OSSEC'

    if 'name' in input:
        name = input['name']
        command = command + f" A:'{name}'"
    else:
        raise Exception("Error creating the Authd command: 'name' is required")

    if 'group' in input:
        group = input['group']
        command = command + f" G:'{group}'"

    if 'ip' in input:
        ip = input['ip']
        command = command + f" IP:'{ip}'"

    if 'key_hash' in input:
        key_hash = input['key_hash']
        command = command + f" K:'{key_hash}'"

    return command

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


def parse_authd_response(response):
    """
    Parses an Authd response into a dictionary.

    Args:
        response (str): Raw response received from Authd.
    Returns:
        dict: Parsed components of the response.
    """
    response_dict = {}
    try:
        header, payload = response.split(sep=' ', maxsplit=1)
        if header == 'OSSEC':
            response_dict['status'] = 'success'
            # The agent key is sent within '' and each component is separated by white spaces:
            # K:'001 agent_name any TopSecret
            agent_key = payload.split('\'')[1]
            response_dict['id'], response_dict['name'], response_dict['ip'], response_dict['key'] = agent_key.split(' ')
        elif header == 'ERROR:':
            response_dict['status'] = 'error'
            response_dict['message'] = payload
        else:
            raise

    except Exception:
        raise IndexError(f"Authd response does not have the expected format: '{response}'")
    return response_dict


def validate_authd_response(response, expected):
    """
    Validates if the different items of an Authd response are as expected. Any item inexistent in expected won't
    be validated.
    Args:
        response (str): The Authd response to be validated.
        expected (dict): Dictionary with the items to validate.
    """
    response_dict = parse_authd_response(response)

    for key in expected.keys():
        if re.match(expected[key], response_dict[key]) is None:
            return 'error', f"Invalid {key}: '{response_dict[key]}' received, '{expected[key]}' expected"
    return 'success', ''
