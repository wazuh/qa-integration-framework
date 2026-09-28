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
WAZUH_API_SCRIPT = os.path.join(WAZUH_API_SCRIPTS_FOLDER_PATH, 'wazuh_manager_apid.py')

# Databases paths
RBAC_DATABASE_PATH = os.path.join(WAZUH_API_SECURITY_FOLDER_PATH, 'rbac.db')

# Credentials file shared by the Wazuh components. The manager publishes the passwords it seeds its
# default API users with there. Only root can read it.
CREDENTIALS_FILE_PATH = os.path.join(os.sep, 'etc', 'wazuh', 'credentials.env')

# SSL paths
WAZUH_API_CERTIFICATE = os.path.join(WAZUH_PATH, 'etc', 'certs', 'apid.pem')
