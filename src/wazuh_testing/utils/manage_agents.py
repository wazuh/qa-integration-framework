"""
Copyright (C) 2015-2023, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""
import os
import subprocess
import requests
from typing import List

from wazuh_testing.constants.api import AGENTS_ROUTE
from wazuh_testing.constants.paths import WAZUH_PATH
from wazuh_testing.modules.api.utils import login, get_base_url
from wazuh_testing.utils.database import query_wdb


def remove_agents(agents_id: List, remove_type: str = 'wazuhdb') -> None:
    """Remove agents from manager.

    Args:
        agents_id (list): IDs of different agents to be removed.
        remove_type (str): Choose from where to make the action.

    Raises:
        ValueError: When the type of removal is not correct.
        RuntimeError: When the agent could not be removed via API.
    """
    if remove_type not in ['wazuhdb', 'manage_agents', 'api']:
        raise ValueError(f"Invalid type of agent removal: {remove_type}")

    if agents_id:
        for agent_id in agents_id:
            if remove_type == 'manage_agents':
                subprocess.call([f"{WAZUH_PATH}/bin/manage_agents", "-r", f"{agent_id}"], stdout=open(os.devnull, "w"),
                                stderr=subprocess.STDOUT)
            elif remove_type == 'wazuhdb':
                query_wdb(f"global delete-agent {str(agent_id)}")
        if remove_type == 'api':
            authentication_headers, _ = login()
            url = get_base_url() + AGENTS_ROUTE
            payload = {
                'agents_list': agents_id,
                'status': 'all',
                'older_than': '0s'
            }
            response = requests.delete(url, headers=authentication_headers, params=payload, verify=False)
            response_data = response.json()
            if response.status_code != 200:
                raise RuntimeError(f"Error deleting an agent: {response_data}")
