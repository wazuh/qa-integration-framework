# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import re


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

    command += '\n'
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
