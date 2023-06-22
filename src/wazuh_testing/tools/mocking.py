# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
import time

from wazuh_testing.constants.paths.sockets import QUEUE_DB_PATH
from wazuh_testing.utils import client_keys, file, services
from wazuh_testing.utils.db_queries import global_db, agent_db

def create_mocked_agent(name='centos8-agent', ip='127.0.0.1', register_ip='127.0.0.1', internal_key='',
                        os_name='CentOS Linux', os_version='8.4', os_major='8', os_minor='4', os_codename='centos-8',
                        os_build='4.18.0-147.8.1.el8_1.x86_64', os_platform='#1 SMP Thu Apr 9 13:49:54 UTC 2020',
                        os_uname='x64', os_arch='x64', version='Wazuh v4.3.0', config_sum='', merged_sum='',
                        manager_host='centos-8', node_name='node01', date_add='1612942494', hostname='centos-8',
                        last_keepalive='253402300799', group='', sync_status='synced', connection_status='active',
                        client_key_secret=None, os_release='', os_patch='', release='', sysname='Linux',
                        checksum='checksum', os_display_version='', triaged='0', reference='', disconnection_time='0',
                        architecture='x64'):

    """Mock a new agent creating a new client keys entry, adding it to the global db and creating a new agent id DB.

    Args:
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
        hostname (str): Hostname.
        last_keepalive (str): Last keep alive timestamp reported.
        group (str): Group of the agent.
        sync_status (str): Status of the syncronization.
        connection_status (str): Status of the connection.
        client_key_secret (str): Client secret key.
        os_release (str): Os release.
        os_patch (str): Os patch.
        release (str): Release.
        sysname (str): System name.
        checksum (str): Checksum.
        os_display_version (str): OS displayed version.
        triaged (str): Triaged.
        reference (str): Reference.
        disconnection_time (str): Last disconnection time.
        architecture (str): Architecture.

    Return:
        str: Agent ID.
    """

    # Get new agent_id
    last_id = global_db.get_last_agent_id()
    agent_id = int(last_id) + 1
    agent_id_str = str(agent_id).zfill(3)  # Convert from x to 00x

    client_keys.add_client_keys_entry(agent_id_str, name, ip, client_key_secret)

    # Create the new agent
    global_db.create_or_update_agent(agent_id=agent_id_str, name=name, ip=ip, register_ip=register_ip,
                                     internal_key=internal_key, os_name=os_name, os_version=os_version,
                                     os_major=os_major, os_minor=os_minor, os_codename=os_codename, os_build=os_build,
                                     os_platform=os_platform, os_uname=os_uname, os_arch=os_arch, version=version,
                                     config_sum=config_sum, merged_sum=merged_sum, manager_host=manager_host,
                                     node_name=node_name, date_add=date_add, last_keepalive=last_keepalive, group=group,
                                     sync_status=sync_status, connection_status=connection_status,
                                     disconnection_time=disconnection_time)

    # Restart Wazuh-DB before creating new DB
    services.control_service('restart', daemon='wazuh-db')

    # sleep is needed since, without it, the agent database creation may fail
    time.sleep(3)

    # Add or update os_info related to the new created agent
    agent_db.update_os_info(agent_id=agent_id_str, hostname=hostname, architecture=os_arch, os_name=os_name,
                            os_version=os_version, os_codename=os_codename, os_major=os_major, os_minor=os_minor,
                            os_patch=os_patch, os_build=os_build, os_platform=os_platform, sysname=sysname,
                            release=release, version=version, os_release=os_release, checksum=checksum,
                            os_display_version=os_display_version, triaged=triaged, reference=reference)

    return agent_id_str


def delete_mocked_agent(agent_id):
    """Delete a mocked agent removing it from the global db, client keys and db file.

    Args:
        agent_id (str): Agent ID.
    """
    # Remove from global db
    global_db.delete_agent(agent_id)

    # Remove agent id DB file if exists
    file.remove_file(os.path.join(QUEUE_DB_PATH, f"{agent_id}.db"))

    # Remove entry from client keys
    client_keys.delete_client_keys_entry(agent_id)
