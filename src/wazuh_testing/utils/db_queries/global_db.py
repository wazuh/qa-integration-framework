# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
from wazuh_testing.utils import database
import json
import hashlib

def create_or_update_agent(agent_id='001', name='centos8-agent', ip='127.0.0.1', register_ip='127.0.0.1',
                           internal_key='', os_name='CentOS Linux', os_version='8.4', os_major='8', os_minor='4',
                           os_codename='centos-8', os_build='4.18.0-147.8.1.el8_1.x86_64',
                           os_platform='#1 SMP Thu Apr 9 13:49:54 UTC 2020', os_uname='x86_64', os_arch='x86_64',
                           version='Wazuh v4.3.0', config_sum='', merged_sum='', manager_host='centos-8',
                           node_name='node01', date_add='1612942494', last_keepalive='253402300799', group='',
                           sync_status='synced', connection_status='active', disconnection_time='0', status_code='0'):
    """Create an agent or update its info if it already exists (checking agent_id).

    Args:
        agent_id (str): Agent ID.
        name (str): Agent name.
        ip (str): Agent IP.
        register_ip (str): IP of the registered agent.
        internal_key (str): Internal key of the agent.
        os_name (str): Name of the OS.
        os_version (str): Version of the OS.
        os_major (str): Major version of the OS supported.
        os_minor (str): Minor version of the OS supported.
        os_codename (str): Codename of the OS.
        os_build (str): Build id of the OS.
        os_platform (str): Platform version of the OS.
        os_uname (str): Version and architecture of the OS.
        os_arch (str): Architecture of the OS.
        version (str): Version of the agent.
        config_sum (str): .
        merged_sum (str): .
        manager_host (str): Name of the manager.
        node_name (str): Name of the node.
        date_add (str): Date of the added/updated agent.
        last_keepalive (str): Last keep alive timestamp reported.
        group (str): Group of the agent.
        sync_status (str): Status of the syncronization.
        connection_status (str): Status of the connection.
        disconnection_time (str): Last disconnection time.
        status_code (str): Last status code.
    """
    query = 'global sql INSERT OR REPLACE INTO AGENT  (id, name, ip, register_ip, internal_key, os_name, os_version, ' \
            'os_major, os_minor, os_codename, os_build, os_platform, os_uname, os_arch, version, config_sum, ' \
            'merged_sum, manager_host, node_name, date_add, last_keepalive, "group", sync_status, connection_status, ' \
            f"disconnection_time, status_code) VALUES  ('{agent_id}', '{name}', '{ip}', '{register_ip}', '{internal_key}', " \
            f"'{os_name}', '{os_version}', '{os_major}', '{os_minor}', '{os_codename}', '{os_build}', " \
            f"'{os_platform}', '{os_uname}', '{os_arch}', '{version}', '{config_sum}', '{merged_sum}', " \
            f"'{manager_host}', '{node_name}', '{date_add}', '{last_keepalive}', '{group}', '{sync_status}', " \
            f"'{connection_status}', '{disconnection_time}', '{status_code}')"

    database.query_wdb(query)


def get_last_agent_id():
    """Get the last agent ID registered in the global DB.

    Returns:
        str: Agent ID.
    """
    last_id = database.query_wdb('global sql SELECT id FROM agent order by id desc limit 1')
    return last_id[0]['id']


def delete_agent(agent_id = None):
    """Delete one or all agents from the global.db

    Args:
        agent_id (str): Agent ID. If empty, deletes all agents.
    """
    if agent_id == None:
        id = "id != 0"
    else:
        id = f"id = {int(agent_id)}"
    database.query_wdb(f"global sql DELETE FROM agent where {id}")


# Insert agents into DB and assign them into a group
def insert_agent_into_group(agent_id, groups_list):
    groups = json.dumps(groups_list)
    command = f'''global set-agent-groups {{"mode":"append","sync_status":"syncreq",
                "source":"remote","data":[{{"id":{agent_id},"groups":{groups}}}]}}'''
    results = database.query_wdb(command)
    assert results == 'ok'


def calculate_global_hash():
    """Function that calculates and retrieves the actual global groups hash.

    Returns:
        str: Actual global groups hash.
    """
    GET_GROUP_HASH = '''global sql SELECT group_hash FROM agent WHERE
                     id > 0 AND group_hash IS NOT NULL ORDER BY id'''

    result = database.query_wdb(GET_GROUP_HASH)
    group_hashes = [item['group_hash'] for item in result]

    return hashlib.sha1("".join(group_hashes).encode()).hexdigest()


def clean_groups_from_db():
    """
    Clean groups table from global.db
    """
    command = 'global sql DELETE FROM "group"'
    try:
        database.query_wdb(command)
    except Exception:
        raise Exception('Unable to clean groups table.')


def clean_belongs():
    """
    Clean belong table from global.db
    """
    command = 'global sql DELETE FROM belongs'
    try:
        database.query_wdb(command)
    except Exception:
        raise Exception('Unable to clean belongs table.')


def insert_metadata_value(key, value):
    """
    Clean belong table from global.db
    """
    command = f'global sql insert into metadata (key,value) VALUES ("{key}","{value}")'
    try:
        database.query_wdb(command)
    except Exception:
        raise Exception('Unable to insert value')


def remove_metadata_value(key):
    """
    Clean belong table from global.db
    """
    command = f'global sql delete from metadata where key="{key}"'
    try:
        database.query_wdb(command)
    except Exception:
        raise Exception('Unable to remove value')
