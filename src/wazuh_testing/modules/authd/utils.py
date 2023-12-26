# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import re
import os
import time

from wazuh_testing.constants.paths.sockets import QUEUE_AGENTS_TIMESTAMP_PATH, QUEUE_DIFF_PATH, QUEUE_RIDS_PATH
from wazuh_testing.utils.file import truncate_file, remove_file, recursive_directory_creation


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


def check_diff(name, expected, timeout=30):
    diff_path = os.path.join(QUEUE_DIFF_PATH, name)
    wait = time.time() + timeout
    while time.time() < wait:
        ret = os.path.exists(diff_path)
        if ret == expected:
            return True
    return False


def check_rids(id, expected):
    agent_info_path = os.path.join(QUEUE_RIDS_PATH, id)
    if expected == os.path.exists(agent_info_path):
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
