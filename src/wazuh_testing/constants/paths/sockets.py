# Copyright (C) 2015-2023, Wazuh Inc.
# Created by Wazuh, Inc. <info@wazuh.com>.
# This program is free software; you can redistribute it and/or modify it under the terms of GPLv2
import os

from . import WAZUH_PATH


QUEUE_CLUSTER_PATH = os.path.join(WAZUH_PATH, 'queue', 'cluster')
QUEUE_DB_PATH = os.path.join(WAZUH_PATH, 'queue', 'db')
QUEUE_SOCKETS_PATH = os.path.join(WAZUH_PATH, 'queue', 'sockets')
QUEUE_AGENTS_TIMESTAMP_PATH = os.path.join(WAZUH_PATH, 'queue', 'agents-timestamp')
QUEUE_DIFF_PATH = os.path.join(WAZUH_PATH, 'queue', 'diff')
QUEUE_RIDS_PATH = os.path.join(WAZUH_PATH, 'queue', 'rids')
QUEUE_ALERTS_PATH = os.path.join(WAZUH_PATH, 'queue', 'alerts')
DIFF_PATH_FILE = os.path.join(QUEUE_DIFF_PATH, 'file')

ANALYSISD_ANALISIS_SOCKET_PATH = os.path.join(QUEUE_SOCKETS_PATH, 'engine-api-http.sock')
ANALYSISD_QUEUE_SOCKET_PATH = os.path.join(QUEUE_SOCKETS_PATH, 'queue')
AUTHD_SOCKET_PATH = os.path.join(QUEUE_SOCKETS_PATH, 'auth.sock')
EXECD_SOCKET_PATH = os.path.join(QUEUE_SOCKETS_PATH, 'com')
LOGCOLLECTOR_SOCKET_PATH = os.path.join(QUEUE_SOCKETS_PATH, 'logcollector')
MODULESD_WMODULES_SOCKET_PATH = os.path.join(QUEUE_SOCKETS_PATH, 'wmodules')
MODULESD_CONTROL_SOCKET_PATH = os.path.join(QUEUE_SOCKETS_PATH, 'control')
# The manager renamed these two; the agent keeps the legacy names, so each product
# needs its own constant.
MANAGER_WMODULES_SOCKET_PATH = os.path.join(QUEUE_SOCKETS_PATH, 'wmodules.sock')
MANAGER_CONTROL_SOCKET_PATH = os.path.join(QUEUE_SOCKETS_PATH, 'control.sock')
MODULESD_C_INTERNAL_SOCKET_PATH = os.path.join(QUEUE_SOCKETS_PATH, 'cluster-internal.sock')
MONITORD_SOCKET_PATH = os.path.join(QUEUE_SOCKETS_PATH, 'monitor.sock')
REMOTED_SOCKET_PATH = os.path.join(QUEUE_SOCKETS_PATH, 'remote.sock')
SYSCHECKD_SOCKET_PATH = os.path.join(QUEUE_SOCKETS_PATH, 'syscheck')
WAZUH_DB_SOCKET_PATH = os.path.join(QUEUE_SOCKETS_PATH, 'wdb.sock')


WAZUH_SOCKETS = {
    'wazuh-agentd': [],
    'wazuh-manager-apid': [],
    'wazuh-manager-analysisd': [
        ANALYSISD_ANALISIS_SOCKET_PATH,
    ],
    'wazuh-manager-authd': [AUTHD_SOCKET_PATH],
    'wazuh-execd': [EXECD_SOCKET_PATH],
    'wazuh-logcollector': [LOGCOLLECTOR_SOCKET_PATH],
    'wazuh-manager-monitord': [MONITORD_SOCKET_PATH],
    'wazuh-manager-remoted': [REMOTED_SOCKET_PATH],
    'wazuh-syscheckd': [SYSCHECKD_SOCKET_PATH],
    'wazuh-manager-db': [WAZUH_DB_SOCKET_PATH],
    'wazuh-modulesd': [
        MODULESD_WMODULES_SOCKET_PATH,
        MODULESD_CONTROL_SOCKET_PATH,
    ],
    'wazuh-manager-modulesd': [
        MANAGER_WMODULES_SOCKET_PATH,
        MANAGER_CONTROL_SOCKET_PATH,
    ],
    'wazuh-manager-clusterd': [MODULESD_C_INTERNAL_SOCKET_PATH]
}

# These sockets do not exist with default Wazuh configuration
WAZUH_OPTIONAL_SOCKETS = [
    AUTHD_SOCKET_PATH
]
