# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
from base64 import b64encode
from random import choices, randrange
from string import ascii_lowercase, digits
from struct import pack
import re
import os
import subprocess
import time

from cryptography.fernet import Fernet

from wazuh_testing.constants.paths.sockets import QUEUE_AGENTS_TIMESTAMP_PATH, QUEUE_DIFF_PATH, QUEUE_RIDS_PATH
from wazuh_testing.constants.paths.configurations import WAZUH_CLIENT_KEYS_PATH
from wazuh_testing.utils.file import truncate_file, remove_file, recursive_directory_creation

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


def clean_diff():
    try:
        remove_file(QUEUE_DIFF_PATH)
        recursive_directory_creation(QUEUE_DIFF_PATH)
        os.chmod(QUEUE_DIFF_PATH, 0o777)
    except Exception as e:
        print('Failed to delete %s. Reason: %s' % (QUEUE_DIFF_PATH, e))


def clean_rids():
    for filename in os.listdir(QUEUE_RIDS_PATH):
        file_path = os.path.join(QUEUE_RIDS_PATH, filename)
        if "sender_counter" not in file_path:
            try:
                os.unlink(file_path)
            except Exception as e:
                print('Failed to delete %s. Reason: %s' % (file_path, e))


def clean_agents_timestamp():
    truncate_file(QUEUE_AGENTS_TIMESTAMP_PATH)


def check_agent_groups(id, expected, timeout=30):
    subprocess.call(['/var/ossec/bin/agent_groups', '-s', '-i', id, '-q'])
    wait = time.time() + timeout
    while time.time() < wait:
        groups_created = subprocess.check_output("/var/ossec/bin/agent_groups")
        if expected in str(groups_created):
            return True
    return False


def check_diff(name, expected, timeout=30):
    diff_path = os.path.join(QUEUE_DIFF_PATH, name)
    wait = time.time() + timeout
    while time.time() < wait:
        ret = os.path.exists(diff_path)
        if ret == expected:
            return True
    return False


def check_client_keys(id, expected):
    found = False
    try:
        with open(WAZUH_CLIENT_KEYS_PATH) as client_file:
            client_lines = client_file.read().splitlines()
            for line in client_lines:
                data = line.split(" ")
                if data[0] == id:
                    found = True
                    break
    except IOError:
        raise

    if found == expected:
        return True
    else:
        return False


def check_agent_timestamp(id, name, ip, expected):
    line = "{} {} {}".format(id, name, ip)
    found = False
    try:
        with open(QUEUE_AGENTS_TIMESTAMP_PATH) as file:
            file_lines = file.read().splitlines()
            for file_line in file_lines:
                if line in file_line:
                    found = True
                    break
    except IOError:
        raise
    if found == expected:
        return True
    else:
        return False


def check_rids(id, expected):
    agent_info_path = os.path.join(QUEUE_RIDS_PATH, id)
    if expected == os.path.exists(agent_info_path):
        return True
    else:
        return False


def create_rids(id):
    rids_path = os.path.join(QUEUE_RIDS_PATH, id)
    try:
        file = open(rids_path, 'w')
        file.close()
        os.chmod(rids_path, 0o777)
    except IOError:
        raise


def create_diff(name):
    SIGID = '533'
    diff_folder = os.path.join(QUEUE_DIFF_PATH, name)
    try:
        os.mkdir(diff_folder)
    except IOError:
        raise

    sigid_folder = os.path.join(diff_folder, SIGID)
    try:
        os.mkdir(sigid_folder)
    except IOError:
        raise

    last_entry_path = os.path.join(sigid_folder, 'last-entry')
    try:
        file = open(last_entry_path, 'w')
        file.close()
        os.chmod(last_entry_path, 0o777)
    except IOError:
        raise


def register_agent_main_server(receiver_sockets, Name, Group=None, IP=None):
    message = "OSSEC A:'{}'".format(Name)
    if Group:
        message += " G:'{}'".format(Group)
    if IP:
        message += " IP:'{}'".format(IP)

    receiver_sockets[0].open()
    receiver_sockets[0].send(message, size=False)
    timeout = time.time() + 10
    response = ''
    while response == '':
        response = receiver_sockets[0].receive().decode()
        if time.time() > timeout:
            raise ConnectionResetError('Manager did not respond to sent message!')
    time.sleep(5)
    return response


def register_agent_local_server(receiver_sockets, Name, Group=None, IP=None):
    message = ('{"arguments":{"force":{"enabled":true,"disconnected_time":{"enabled":true,"value":"0"},'
               '"key_mismatch":true,"after_registration_time":"0"}')
    message += ',"name":"{}"'.format(Name)
    if Group:
        message += ',"groups":"{}"'.format(Group)
    if IP:
        message += ',"ip":"{}"'.format(IP)
    else:
        message += ',"ip":"any"'
    message += '},"function":"add"}'

    receiver_sockets[1].open()
    receiver_sockets[1].send(message, size=True)
    response = receiver_sockets[1].receive(size=True).decode()
    time.sleep(5)
    return response
