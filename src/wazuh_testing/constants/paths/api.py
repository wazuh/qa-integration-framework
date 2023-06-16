"""
Copyright (C) 2015-2023, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""
import os

from wazuh_testing.constants.paths import WAZUH_PATH

# API paths that do not fit in `configurations`

# Folders
WAZUH_API_FOLDER_PATH = os.path.join(WAZUH_PATH, 'api')
WAZUH_API_SCRIPTS_FOLDER_PATH = os.path.join(WAZUH_API_FOLDER_PATH, 'scripts')

# Logs paths
WAZUH_API_LOG_FILE_PATH = os.path.join(WAZUH_PATH, 'logs', 'api.log')
WAZUH_API_JSON_LOG_FILE_PATH = os.path.join(WAZUH_PATH, 'logs', 'api.json')

# API scripts paths
WAZUH_API_SCRIPT = os.path.join(WAZUH_API_SCRIPTS_FOLDER_PATH,'wazuh-apid.py')
