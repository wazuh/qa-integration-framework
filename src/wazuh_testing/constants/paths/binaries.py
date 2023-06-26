# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
import sys

from . import WAZUH_PATH

if sys.platform == 'win32':
    BIN_PATH = WAZUH_PATH
else:
    BIN_PATH = os.path.join(WAZUH_PATH, 'bin')

WAZUH_CONTROL_PATH = os.path.join(BIN_PATH, 'wazuh-control')
AGENT_AUTH_PATH = os.path.join(BIN_PATH, 'agent-auth')
