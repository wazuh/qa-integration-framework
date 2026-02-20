# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
import sys

from wazuh_testing.constants.platforms import WINDOWS

from . import WAZUH_PATH

if sys.platform == WINDOWS:
    BIN_PATH = WAZUH_PATH
else:
    BIN_PATH = os.path.join(WAZUH_PATH, 'bin')

WAZUH_MANAGER_CONTROL_PATH = os.path.join(BIN_PATH, 'wazuh-manager-control')
WAZUH_AGENT_CONTROL_PATH = os.path.join(BIN_PATH, 'wazuh-control')
WAZUH_CONTROL_PATH = WAZUH_MANAGER_CONTROL_PATH if os.path.basename(os.path.normpath(WAZUH_PATH)) == 'wazuh-manager' \
    else WAZUH_AGENT_CONTROL_PATH
ACTIVE_RESPONSE_BIN_PATH = os.path.join(WAZUH_PATH, 'active-response', 'bin')
ACTIVE_RESPONSE_FIREWALL_DROP = os.path.join(ACTIVE_RESPONSE_BIN_PATH, 'firewall-drop')
AGENT_GROUPS_BINARY = os.path.join(BIN_PATH, 'agent_groups')
