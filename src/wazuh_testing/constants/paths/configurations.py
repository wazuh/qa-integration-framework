"""
Copyright (C) 2015-2023, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""
import os
import sys

from wazuh_testing.constants.platforms import WINDOWS

from . import WAZUH_PATH
from wazuh_testing.constants.paths.api import WAZUH_API_FOLDER_PATH, WAZUH_API_SECURITY_FOLDER_PATH


if sys.platform == WINDOWS:
    BASE_CONF_PATH = WAZUH_PATH
else:
    BASE_CONF_PATH = os.path.join(WAZUH_PATH, 'etc')

WAZUH_CLIENT_KEYS_PATH = os.path.join(BASE_CONF_PATH, 'client.keys')
SHARED_CONFIGURATIONS_PATH = os.path.join(BASE_CONF_PATH, 'shared')
WAZUH_CONF_PATH = os.path.join(BASE_CONF_PATH, 'ossec.conf')
WAZUH_LOCAL_INTERNAL_OPTIONS = os.path.join(BASE_CONF_PATH, 'local_internal_options.conf')
ACTIVE_RESPONSE_CONFIGURATION = os.path.join(SHARED_CONFIGURATIONS_PATH, 'ar.conf')
AR_CONF = os.path.join(SHARED_CONFIGURATIONS_PATH, 'ar.conf')
CUSTOM_RULES_PATH = os.path.join(BASE_CONF_PATH, 'rules')
CUSTOM_RULES_FILE = os.path.join(CUSTOM_RULES_PATH, 'local_rules.xml')
CIS_RULESET_PATH = os.path.join(WAZUH_PATH, 'ruleset', 'sca')

# Wazuh API configurations path
WAZUH_API_CONFIGURATION_PATH = os.path.join(WAZUH_API_FOLDER_PATH, 'configuration', 'api.yaml')
WAZUH_SECURITY_CONFIGURATION_PATH = os.path.join(WAZUH_API_SECURITY_FOLDER_PATH, 'security.yaml')
