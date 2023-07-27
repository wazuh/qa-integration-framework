# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
import sys

from wazuh_testing.constants.platforms import WINDOWS

from . import WAZUH_PATH


VAR_PATH = os.path.join(WAZUH_PATH, 'var')
VAR_RUN_PATH = os.path.join(VAR_PATH, 'run')

ANALYSISD_STATE = os.path.join(VAR_RUN_PATH, 'wazuh-analysisd.state')

if sys.platform == WINDOWS:
    VERSION_FILE = os.path.join(WAZUH_PATH, 'VERSION')
    AGENTD_STATE = os.path.join(WAZUH_PATH, 'wazuh-agent.state')
else:
    VERSION_FILE = ''
    AGENTD_STATE = os.path.join(VAR_RUN_PATH, 'wazuh-agent.state')
