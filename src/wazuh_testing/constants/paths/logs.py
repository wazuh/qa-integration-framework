# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
import sys

from . import WAZUH_PATH


BASE_LOGS_PATH = os.path.join(WAZUH_PATH, 'logs')

if sys.platform == 'win32':
    WAZUH_LOG_PATH = os.path.join(WAZUH_PATH, 'ossec.log')
    BASE_LOGS_PATH = os.path.join(WAZUH_PATH)
    ACTIVE_RESPONSE_LOG_PATH = os.path.join(BASE_LOGS_PATH, 'active-response', 'active-responses.log')
else:
    WAZUH_LOG_PATH = os.path.join(BASWE_LOGS_PATH, 'ossec.log')
    ACTIVE_RESPONSE_LOG_PATH = os.path.join(BASE_LOGS_PATH, 'active-responses.log')

ALERTS_LOG_PATH = os.path.join(BASE_LOGS_PATH, 'alerts', 'alerts.log')
ALERTS_JSON_PATH = os.path.join(BASE_LOGS_PATH, 'alerts', 'alerts.json')
ARCHIVES_LOG_PATH = os.path.join(BASE_LOGS_PATH, 'archives', 'archives.log')
ARCHIVES_JSON_PATH = os.path.join(BASE_LOGS_PATH, 'archives', 'archives.json')
