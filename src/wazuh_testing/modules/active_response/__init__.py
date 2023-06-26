# Copyright (C) 2015-2021, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os

from wazuh_testing.constants.paths import WAZUH_PATH

# Active response binaries path
ACTIVE_RESPONSE_BINARIES = os.path.join(WAZUH_PATH, 'active-response', 'bin')
FIREWALL_DROP_BIN = os.path.join(ACTIVE_RESPONSE_BINARIES, 'firewall-drop')
