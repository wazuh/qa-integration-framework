# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
import sys

from wazuh_testing.constants.platforms import WINDOWS
from wazuh_testing.constants.daemons import WAZUH_MANAGER
from wazuh_testing.utils.services import get_service

from . import WAZUH_PATH


BASE_LOGS_PATH = os.path.join(WAZUH_PATH, 'logs')

if sys.platform == WINDOWS:
    BASE_LOGS_PATH = WAZUH_PATH
    ACTIVE_RESPONSE_LOG_PATH = os.path.join(BASE_LOGS_PATH, 'active-response', 'active-responses.log')
else:
    ACTIVE_RESPONSE_LOG_PATH = os.path.join(BASE_LOGS_PATH, 'active-responses.log')

try:
    _is_manager = get_service() == WAZUH_MANAGER
except Exception:
    _is_manager = False

WAZUH_LOG_PATH = os.path.join(BASE_LOGS_PATH, 'wazuh-manager.log' if _is_manager else 'ossec.log')
ALERTS_LOG_PATH = os.path.join(BASE_LOGS_PATH, 'alerts', 'alerts.log')
ALERTS_JSON_PATH = os.path.join(BASE_LOGS_PATH, 'alerts', 'alerts.json')
ARCHIVES_LOG_PATH = os.path.join(BASE_LOGS_PATH, 'archives', 'archives.log')
ARCHIVES_JSON_PATH = os.path.join(BASE_LOGS_PATH, 'archives', 'archives.json')

# API logs paths
WAZUH_API_LOG_FILE_PATH = os.path.join(BASE_LOGS_PATH, 'api.log')
WAZUH_API_JSON_LOG_FILE_PATH = os.path.join(BASE_LOGS_PATH, 'api.json')

WAZUH_CLUSTER_LOGS_PATH = os.path.join(BASE_LOGS_PATH, 'cluster.log')

MACOS_LOG_COMMAND_PATH = '/usr/bin/log'
