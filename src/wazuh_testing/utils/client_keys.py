# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import random
from typing import List

from wazuh_testing.constants.paths.configurations import WAZUH_CLIENT_KEYS_PATH
from wazuh_testing.utils import file


def add_client_keys_entry(agent_id: str, agent_name: str, agent_ip: str = 'any', agent_key: str = None) -> None:
    """Add new entry to client keys file. If the agent_id already exists, this will be overwritten.

    Args:
        agent_id (str): Agent identifier.
        agent_name (str): Agent name.
        agent_ip (str): Agent ip.
        agent_key (str): Agent key.
    """
    registered_client_key_entries_dict = {}

    # Generate new key if necessary
    if agent_key is None:
        agent_key = ''.join(random.choice('0123456789abcdef') for i in range(64))

    # Read client keys data
    with open(WAZUH_CLIENT_KEYS_PATH, 'r') as client_keys:
        registered_client_key_entries_str = client_keys.readlines()

    # Process current client key entries
    for client_key_entry in registered_client_key_entries_str:
        _agent_id, _agent_name, _agent_ip, _agent_key = client_key_entry.split()
        registered_client_key_entries_dict[_agent_id] = f"{_agent_id} {_agent_name} {_agent_ip} {_agent_key}"

    # Add the new client key entry
    registered_client_key_entries_dict[agent_id] = f"{agent_id} {agent_name} {agent_ip} {agent_key}"

    # Save new client keys content
    with open(WAZUH_CLIENT_KEYS_PATH, 'w') as client_keys:
        for _, client_key_entry in registered_client_key_entries_dict.items():
            client_keys.write(f"{client_key_entry}\n")


def delete_client_keys_entry(agent_id: str) -> None:
    """Delete an entry from client keys file.

    Args:
        agent_id (str): Agent identifier.
    """
    registered_client_key_entries_dict = {}

    # Read client keys data
    with open(WAZUH_CLIENT_KEYS_PATH, 'r') as client_keys:
        registered_client_key_entries_str = client_keys.readlines()

    # Process current client key entries
    for client_key_entry in registered_client_key_entries_str:
        _agent_id, _agent_name, _agent_ip, _agent_key = client_key_entry.split()
        registered_client_key_entries_dict[_agent_id] = f"{_agent_id} {_agent_name} {_agent_ip} {_agent_key}"

    # Remove client key entry
    registered_client_key_entries_dict.pop(agent_id, None)

    # Save new client keys content
    with open(WAZUH_CLIENT_KEYS_PATH, 'w') as client_keys:
        for _, client_key_entry in registered_client_key_entries_dict.items():
            client_keys.write(f"{client_key_entry}\n")


def get_client_keys(path: str = WAZUH_CLIENT_KEYS_PATH) -> List[dict]:
    """Get client keys from a file.

    Args:
        path (str, optional): Path to the file containing the client keys.
            Defaults to WAZUH_CLIENT_KEYS_PATH.

    Returns:
        List[dict]: A list of dictionaries representing the client keys.
            Each dictionary contains the following keys: 'id', 'name', 'ip', and 'key'.
    """
    if not file.exists_and_is_file(path):
        return [{'id': '001', 'name': 'ubuntu-agent', 'ip': 'any', 'key': 'SuperSecretKey'}]

    keys = []
    for line in file.read_file_lines(path):
        (id, name, ip, key) = line.replace('\n', '').split(' ')
        keys.append({'id': id, 'name': name, 'ip': ip, 'key': key})

    return keys


def check_client_keys(id, expected):
    """Check key of a given agent

    Args:
        id (str): Agent id
        expected (str): Key expected

    Returns:
        True if key exists for agent, False otherwise
    """
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
