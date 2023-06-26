# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os
import sys

from . import WAZUH_PATH


CONF_PATH = os.path.join(WAZUH_PATH, 'etc')

if sys.platform == 'win32':
    WAZUH_CONF_PATH = os.path.join(WAZUH_PATH, 'ossec.conf')
    WAZUH_LOCAL_INTERNAL_OPTIONS = os.path.join(WAZUH_PATH, 'local_internal_options.conf')
    WAZUH_CLIENT_KEYS_PATH = os.path.join(WAZUH_PATH, 'client.keys')
else:
    WAZUH_CONF_PATH = os.path.join(CONF_PATH, 'ossec.conf')
    WAZUH_LOCAL_INTERNAL_OPTIONS = os.path.join(CONF_PATH, 'local_internal_options.conf')
    WAZUH_CLIENT_KEYS_PATH = os.path.join(CONF_PATH, 'client.keys')

CUSTOM_RULES_PATH = os.path.join(CONF_PATH, 'rules')
CUSTOM_RULES_FILE = os.path.join(CUSTOM_RULES_PATH, 'local_rules.xml')
