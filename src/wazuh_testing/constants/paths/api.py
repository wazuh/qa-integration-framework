"""
Copyright (C) 2015-2023, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""
import os

from . import WAZUH_PATH, MANAGER_CONF_DIR

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

# Where the manager publishes the passwords it seeds its default API users with (wazuh/wazuh#40339):
# export/credentials.env in its configuration directory, root:root 0600, so only root can read it.
CREDENTIALS_FILE_PATH = os.path.join(MANAGER_CONF_DIR, 'export', 'credentials.env')

# SSL paths
WAZUH_API_CERTIFICATE = os.path.join(MANAGER_CONF_DIR, 'certs', 'apid.pem')
# Trust anchor for the API's certificate: since wazuh/wazuh#40053 the installer issues apid.pem signed by the
# manager CA (it is no longer self-signed), so clients verify it against the CA, as server 'localhost'.
WAZUH_API_CA_CERTIFICATE = os.path.join(MANAGER_CONF_DIR, 'certs', 'root-ca.pem')
