"""
Copyright (C) 2015-2023, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""

CONFIGURATION_TYPES = ('base', 'security')
API_PROTOCOL = 'https'
API_HOST = 'localhost'
API_PORT = '55000'
API_USER = 'wazuh'
API_PASSWORD = 'wazuh'
LOGIN_ROUTE = '/security/user/authenticate'
RULES_FILES_ROUTE = '/rules/files'
