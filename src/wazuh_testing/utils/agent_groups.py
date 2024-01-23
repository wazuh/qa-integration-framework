# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import subprocess
import time

from wazuh_testing.constants.paths.binaries import AGENT_GROUPS_BINARY


def create_group(group):
    """Create group with /var/ossec/bin/agent_groups

    Args:
        group (str): Group name

    Returns:
        result(str): Return code
    """
    result = subprocess.run([AGENT_GROUPS_BINARY, '-a', '-q', '-g', f'{group}']).returncode

    return result


def delete_group(group):
    """Delete group with /var/ossec/bin/agent_groups

    Args:
        group (str): Group name

    Returns:
        result(str): Return code
    """
    result = subprocess.run([AGENT_GROUPS_BINARY, '-r', '-q', '-g', f'{group}']).returncode

    return result


def add_agent_to_group(group, agent_id):
    """Add agent to group with /var/ossec/bin/agent_groups

    Args:
        group (str): Group name
        agent_id (str): Agent ID

    Returns:
        result(str): Return code
    """
    result = subprocess.run([AGENT_GROUPS_BINARY, "-q", "-a", "-i", agent_id, "-g", group]).returncode

    return result


def check_agent_groups(id, expected, timeout=30):
    """Check groups of a given agent with /var/ossec/bin/agent_groups

    Args:
        id (str): Agent id
        expected (str): Group expected
        timeout (int): Time limit to check for agent group

    Returns:
        True if group exists in agent, False otherwise
    """
    subprocess.call([AGENT_GROUPS_BINARY, '-s', '-i', id, '-q'])
    wait = time.time() + timeout
    while time.time() < wait:
        groups_created = subprocess.check_output(AGENT_GROUPS_BINARY)
        if expected in str(groups_created):
            return True
    return False
