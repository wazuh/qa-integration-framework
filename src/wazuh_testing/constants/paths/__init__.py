# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import sys
import os

from wazuh_testing.constants.platforms import MACOS, WINDOWS

TEMP_FILE_PATH = '/tmp'

if sys.platform == WINDOWS:
    WAZUH_PATH = os.path.join("C:", os.sep, "Program Files (x86)", "ossec-agent")
    ROOT_PREFIX = os.path.join('c:', os.sep)

elif sys.platform == MACOS:
    WAZUH_PATH = os.path.join("/", "Library", "Ossec")
    ROOT_PREFIX = os.path.join('/', 'private', 'var', 'root')

else:
    WAZUH_PATH = os.path.join("/", "var", "ossec")
    ROOT_PREFIX = os.sep

WAZUH_PATH_OVERRIDE = os.getenv("WAZUH_PATH") or os.getenv("INSTALLATION_DIR")
if WAZUH_PATH_OVERRIDE:
    WAZUH_PATH = WAZUH_PATH_OVERRIDE
elif sys.platform not in (WINDOWS, MACOS):
    manager_bin_path = os.path.join("/", "var", "wazuh-manager", "bin")
    agent_bin_path = os.path.join("/", "var", "ossec", "bin")
    manager_exists = os.path.exists(os.path.join(manager_bin_path, "wazuh-manager-control"))
    agent_exists = os.path.exists(os.path.join(agent_bin_path, "wazuh-control"))

    # Prefer agent path when both installs are present unless explicitly overridden.
    if manager_exists and not agent_exists:
        WAZUH_PATH = os.path.join("/", "var", "wazuh-manager")

# The manager's configuration directory is fixed (wazuh/wazuh#40338): it does not follow the installation
# directory, so a manager with a custom WAZUH_PATH still keeps its configuration here.
# WAZUH_MANAGER_CONF_DIR overrides it, for a test environment that stages the configuration elsewhere.
MANAGER_CONF_DIR = os.getenv("WAZUH_MANAGER_CONF_DIR") or os.path.join("/", "etc", "wazuh-manager")
