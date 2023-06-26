# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import datetime
import time

from wazuh_testing.utils import database


def insert_os_info(agent_id='000', scan_id=int(time.time()),
                   scan_time=datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S"), hostname='centos8',
                   architecture='x64', os_name='CentOS Linux', os_version='8.4', os_codename='', os_major='8',
                   os_minor='4', os_patch='', os_build='', os_platform='centos', sysname='Linux', release='',
                   version='', os_release='', checksum='dummychecksum', os_display_version='', triaged='0',
                   reference=''):
    """Insert the OS information in the agent database.

    Args:
        agent_id (str): Agent ID.
        scan_id (int): Id of the last scan.
        scan_time (str): Date of the scan with this format "%Y/%m/%d %H:%M:%S".
        hostname (str): Name of the host.
        architecture (str): Architecture of the host.
        os_name (str): Complete name of the OS.
        os_version (str): Version of the OS.
        os_codename (str): OS codename.
        os_major (str): Major version of the OS.
        os_minor (str): Minor version of the OS.
        os_patch (str): Current patch of the OS.
        os_build (str): Build id of the OS.
        os_platform (str): OS platform.
        sysname (str): System name.
        release (str): Release of the OS.
        version (str): Version of the OS.
        os_release (str): Release of the OS.
        checksum (str): Checksum of the OS.
        os_display_version (str): Os displayed version
        triaged (str): Triaged.
        reference (str): OS reference.
    """
    query_string = f"agent {agent_id} sql INSERT OR REPLACE INTO sys_osinfo (scan_id, scan_time, hostname, " \
                   'architecture, os_name, os_version, os_codename, os_major, os_minor, os_patch, os_build, ' \
                   'os_platform, sysname, release, version, os_release, os_display_version, checksum, reference, ' \
                   f"triaged) VALUES ({scan_id}, '{scan_time}', '{hostname}', '{architecture}', '{os_name}', " \
                   f"'{os_version}', '{os_codename}', '{os_major}', '{os_minor}', '{os_patch}', '{os_build}', " \
                   f"'{os_platform}', '{sysname}', '{release}', '{version}', '{os_release}', '{os_display_version}', " \
                   f"'{checksum}', '{reference}', {triaged})"

    database.query_wdb(query_string)


def delete_os_info(agent_id='000'):
    """Delete the sys_osinfo data from a specific agent.

    Args:
        agent_id (str): Agent ID.
    """
    database.query_wdb(f"agent {agent_id} sql DELETE FROM sys_osinfo")


def update_os_info(agent_id='000', scan_id=int(time.time()),
                   scan_time=datetime.datetime.now().strftime("%Y/%m/%d %H:%M:%S"), hostname='centos8',
                   architecture='x64', os_name='CentOS Linux', os_version='8.4', os_codename='', os_major='8',
                   os_minor='4', os_patch='', os_build='', os_platform='centos', sysname='Linux', release='',
                   version='', os_release='', checksum='dummychecksum', os_display_version='', triaged='0',
                   reference=''):
    """Update the sys_osinfo data from a specific agent.

    Args:
        agent_id (str): Agent ID.
        scan_id (int): Id of the last scan.
        scan_time (str): Date of the scan with this format "%Y/%m/%d %H:%M:%S".
        hostname (str): Name of the host.
        architecture (str): Architecture of the host.
        os_name (str): Complete name of the OS.
        os_version (str): Version of the OS.
        os_codename (str): OS codename.
        os_major (str): Major version of the OS.
        os_minor (str): Minor version of the OS.
        os_patch (str): Current patch of the OS.
        os_build (str): Build id of the OS.
        os_platform (str): OS platform.
        sysname (str): System name.
        release (str): Release of the OS.
        version (str): Version of the OS.
        os_release (str): Release of the OS.
        checksum (str): Checksum of the OS.
        os_display_version (str): Os displayed version
        triaged (str): Triaged.
        reference (str): OS reference.
    """
    delete_os_info(agent_id)
    insert_os_info(**locals())
