import os
import subprocess
import requests
from wazuh_testing.constants.paths import WAZUH_PATH

def create_group(group):
    """Create group with /var/ossec/bin/agent_groups

    Args:
        group (str): Group name

    Returns:
        result(str): Return code
    """
    result = subprocess.run([f'{WAZUH_PATH}/bin/agent_groups', '-a', '-q', '-g', f'{group}']).returncode

    return result


def delete_group(group):
    """Delete group with /var/ossec/bin/agent_groups

    Args:
        group (str): Group name

    Returns:
        result(str): Return code
    """
    result = subprocess.run([f'{WAZUH_PATH}/bin/agent_groups', '-r', '-q', '-g', f'{group}']).returncode

    return result