# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import sys
import os
import platform


if sys.platform == 'win32':
    WAZUH_PATH = os.path.join("C:", os.sep, "Program Files (x86)", "ossec-agent")
    ROOT_PREFIX = os.path.join('c:', os.sep)

else:
    if sys.platform == 'darwin':
        WAZUH_PATH = os.path.join("/", "Library", "Ossec")
        ROOT_PREFIX = os.path.join('/', 'private', 'var', 'root')

    else:
        WAZUH_PATH = os.path.join("/", "var", "ossec")
        ROOT_PREFIX = os.sep

CVE_DB_PATH = os.path.join(WAZUH_PATH, 'queue', 'vulnerabilities', 'cve.db')
CLIENT_KEYS_PATH = os.path.join(WAZUH_PATH, 'etc' if platform.system() == 'Linux' else '', 'client.keys')