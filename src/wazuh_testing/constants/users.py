"""
Copyright (C) 2015-2023, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""
import sys

if sys.platform != 'win32':
    import pwd
    import grp

    try:
        pwd.getpwnam('wazuh-manager')
        WAZUH_UNIX_USER = 'wazuh-manager'
    except KeyError:
        WAZUH_UNIX_USER = 'wazuh'

    try:
        grp.getgrnam('wazuh-manager')
        WAZUH_UNIX_GROUP = 'wazuh-manager'
    except KeyError:
        WAZUH_UNIX_GROUP = 'wazuh'
else:
    WAZUH_UNIX_USER = 'wazuh'
    WAZUH_UNIX_GROUP = 'wazuh'
