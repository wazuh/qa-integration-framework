"""
Copyright (C) 2015-2023, Wazuh Inc.
Created by Wazuh, Inc. <info@wazuh.com>.
This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
"""
# API basic information
CONFIGURATION_TYPES = ('base', 'security')
WAZUH_API_PROTOCOL = 'https'
WAZUH_API_HOST = 'localhost'
WAZUH_API_PORT = '55000'
WAZUH_API_USER = 'wazuh'
WAZUH_API_PASSWORD = 'wazuh'
# The users the manager creates by itself, and the variable each one's password is installed through.
# Mirrors PASSWORD_ENVIRONMENT_VARIABLES in the manager's `framework/scripts/rbac_control.py`: one variable
# per user, because an installation can supply one and let the other be generated.
DEFAULT_API_USER_VARIABLES = {WAZUH_API_USER: 'INITIAL_WAZUH_PASSWORD',
                              'wazuh-wui': 'INITIAL_WAZUH_WUI_PASSWORD'}

# API routes
LOGIN_ROUTE = '/security/user/authenticate'
RULES_FILES_ROUTE = '/rules/files'
AGENTS_ROUTE = '/agents'
SYSCOLLECTOR_OS_ROUTE = '/experimental/syscollector/os'
MANAGER_CONFIGURATION_ROUTE = '/manager/configuration'
MANAGER_INFORMATION_ROUTE = '/manager/info'
GROUPS_ROUTE = '/groups'
CDB_LIST_ROUTE = '/lists/files'
DAEMONS_STATS_ROUTE = '/manager/daemons/stats'
# RBAC routes
USERS_ROUTE = '/security/users'
ROLES_ROUTE = '/security/roles'
POLICIES_ROUTE = '/security/policies'
RULES_ROUTE = '/security/rules'
RESOURCE_ROUTE_MAP = {
    'user_ids': USERS_ROUTE,
    'role_ids': ROLES_ROUTE,
    'policy_ids': POLICIES_ROUTE,
    'rule_ids': RULES_ROUTE
}
TARGET_ROUTE_MAP = {
    'user_ids': 'users',
    'role_ids': 'roles',
    'policy_ids': 'policies',
    'rule_ids': 'rules'
}
