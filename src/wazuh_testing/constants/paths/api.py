"""
Copyright (C) 2015-2023, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""
import os

from . import WAZUH_PATH

# API paths that do not fit in `configurations`

# Folders
WAZUH_API_FOLDER_PATH = os.path.join(WAZUH_PATH, 'api')
WAZUH_API_CONFIGURATION_FOLDER_PATH = os.path.join(WAZUH_API_FOLDER_PATH, 'configuration')
WAZUH_API_SECURITY_FOLDER_PATH = os.path.join(WAZUH_API_CONFIGURATION_FOLDER_PATH, 'security')
WAZUH_API_SCRIPTS_FOLDER_PATH = os.path.join(WAZUH_API_FOLDER_PATH, 'scripts')

# API scripts paths
WAZUH_API_SCRIPT = os.path.join(WAZUH_API_SCRIPTS_FOLDER_PATH, 'wazuh_apid.py')

# Databases paths
RBAC_DATABASE_PATH = os.path.join(WAZUH_API_SECURITY_FOLDER_PATH, 'rbac.db')

# SSL paths
WAZUH_API_CERTIFICATE = os.path.join(WAZUH_API_CONFIGURATION_FOLDER_PATH, 'ssl', 'server.crt')
