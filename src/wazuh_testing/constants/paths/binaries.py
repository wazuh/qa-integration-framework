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

WAZUH_CONTROL_PATH = os.path.join(BIN_PATH, 'wazuh-control')
AGENT_AUTH_PATH = os.path.join(BIN_PATH, 'agent-auth')
ACTIVE_RESPONSE_BIN_PATH = os.path.join(WAZUH_PATH, 'active-response', 'bin')
ACTIVE_RESPONSE_FIREWALL_DROP = os.path.join(ACTIVE_RESPONSE_BIN_PATH, 'firewall-drop')
